#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
constexpr unsigned platform_flag = 1U << 31;
constexpr int marker = 424242;
constexpr int target_call = SYS_getpgid;
constexpr const char* fd_payload = "platform-domain-fd-check";
struct Observation { int passed; int value; int error; int extra; };
struct Result { const char* name; bool passed; int platform_events; int application_events; int error; };
struct PlatformInfo { uint64_t flags; uint64_t program_length; };
constexpr unsigned long platform_info_ioctl = _IOR(SECCOMP_IOC_MAGIC, 0x7f, PlatformInfo);
bool transfer(int socket, int platform, int application);
int receive(int socket, int descriptors[2]);
enum class Mode { independent, overlap, deny, trap, forked, threads, executed, addfd };
volatile sig_atomic_t trapped = 0;

int install(int number, unsigned action, unsigned flags) {
    sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(number), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{static_cast<unsigned short>(sizeof(code) / sizeof(code[0])), code};
    return static_cast<int>(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &program));
}

void report(int fd, Observation value) {
    const ssize_t count = write(fd, &value, sizeof(value));
    _exit(count == sizeof(value) && value.passed ? 0 : 1);
}

Observation capacity(bool platform, bool unprivileged) {
    if (unprivileged) {
        if (setgroups(0, nullptr) || setresgid(2000, 2000, 2000) || setresuid(2000, 2000, 2000)) return {0, 0, errno, 0};
        __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
        __user_cap_data_struct capabilities[2]{};
        if (syscall(SYS_capset, &header, capabilities)) return {0, 0, errno, 0};
    }
    int admin = -1;
    if (platform) {
        admin = install(-1, SECCOMP_RET_ALLOW, platform_flag | SECCOMP_FILTER_FLAG_NEW_LISTENER);
        if (admin < 0) return {0, -1, errno, 0};
        const int duplicate = install(-1, SECCOMP_RET_ALLOW, platform_flag | SECCOMP_FILTER_FLAG_NEW_LISTENER);
        const int error = errno;
        if (duplicate >= 0 || error != EBUSY) return {0, duplicate, error, 1};
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return {0, 0, errno, 2};
    const int forbidden = install(-1, SECCOMP_RET_ALLOW, platform_flag | SECCOMP_FILTER_FLAG_NEW_LISTENER);
    const int forbidden_error = errno;
    if (forbidden >= 0 || forbidden_error != EINVAL) return {0, forbidden, forbidden_error, 3};
    const int first = install(-1, SECCOMP_RET_ALLOW, SECCOMP_FILTER_FLAG_NEW_LISTENER);
    if (first < 0) return {0, first, errno, 4};
    PlatformInfo ordinary{};
    const int introspected = ioctl(first, platform_info_ioctl, &ordinary);
    if (introspected != -1 || errno != EINVAL) return {0, introspected, errno, 5};
    const int second = install(-1, SECCOMP_RET_ALLOW, SECCOMP_FILTER_FLAG_NEW_LISTENER);
    const int second_error = errno;
    if (first >= 0) close(first);
    if (admin >= 0) close(admin);
    return {second < 0 && second_error == EBUSY, second, second_error, unprivileged ? static_cast<int>(getuid()) : 0};
}

Observation capacity_child(bool platform, bool unprivileged) {
    int output[2];
    if (pipe2(output, O_CLOEXEC)) return {0, 0, errno, 0};
    pid_t child = fork();
    if (child == 0) { close(output[0]); report(output[1], capacity(platform, unprivileged)); }
    close(output[1]);
    Observation result{};
    if (child < 0 || read(output[0], &result, sizeof(result)) != sizeof(result)) result = {0, 0, errno, 0};
    close(output[0]);
    if (child > 0) { int status; waitpid(child, &status, 0); }
    return result;
}

Result metadata_introspection() {
    int sockets[2], gate[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) || pipe2(gate, O_CLOEXEC))
        return {"root_metadata_and_filter_count", false, 0, 0, errno};
    timeval timeout{3, 0};
    setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    const pid_t child = fork();
    if (child == 0) {
        close(sockets[0]); close(gate[1]);
        const int platform = install(-1, SECCOMP_RET_ALLOW, platform_flag | SECCOMP_FILTER_FLAG_NEW_LISTENER);
        if (platform < 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(1);
        const int application = install(-1, SECCOMP_RET_ALLOW, SECCOMP_FILTER_FLAG_NEW_LISTENER);
        if (application < 0 || !transfer(sockets[1], platform, application)) _exit(1);
        char ready;
        _exit(read(gate[0], &ready, 1) == 1 ? 0 : 1);
    }
    close(sockets[1]); close(gate[0]);
    if (child < 0) { close(sockets[0]); close(gate[1]); return {"root_metadata_and_filter_count", false, 0, 0, errno}; }
    int listeners[2]{-1, -1};
    const bool received = receive(sockets[0], listeners) == 2;
    close(sockets[0]);
    int status = 0;
    bool passed = received;
    if (received) {
        PlatformInfo platform{}, application{};
        passed &= ioctl(listeners[0], platform_info_ioctl, &platform) == 0 && platform.flags == platform_flag && platform.program_length == 7;
        passed &= ioctl(listeners[1], platform_info_ioctl, &application) == -1 && errno == EINVAL;
        char path[64], text[8192]{};
        std::snprintf(path, sizeof(path), "/proc/%d/status", child);
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        const ssize_t length = fd >= 0 ? read(fd, text, sizeof(text) - 1) : -1;
        if (fd >= 0) close(fd);
        passed &= length > 0 && std::strstr(text, "Seccomp_filters:\t2\n") != nullptr;
        const pid_t receiver = fork();
        if (receiver == 0) {
            if (setgroups(0, nullptr) || setresgid(2000, 2000, 2000) || setresuid(2000, 2000, 2000)) _exit(1);
            __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
            __user_cap_data_struct capabilities[2]{};
            if (syscall(SYS_capset, &header, capabilities)) _exit(1);
            PlatformInfo denied{};
            uint64_t invalid_id = 0;
            const bool rejected = ioctl(listeners[0], platform_info_ioctl, &denied) == -1 && errno == EINVAL &&
                ioctl(listeners[0], SECCOMP_IOCTL_NOTIF_ID_VALID, &invalid_id) == -1 && errno == EINVAL;
            _exit(rejected ? 0 : 1);
        }
        int receiver_status = 0;
        passed &= receiver > 0 && waitpid(receiver, &receiver_status, 0) == receiver && WIFEXITED(receiver_status) && WEXITSTATUS(receiver_status) == 0;
        passed &= write(gate[1], "R", 1) == 1;
    } else {
        kill(child, SIGKILL);
    }
    close(gate[1]);
    waitpid(child, &status, 0);
    passed &= WIFEXITED(status) && WEXITSTATUS(status) == 0;
    for (int listener : listeners) if (listener >= 0) close(listener);
    return {"root_metadata_and_filter_count", passed, 0, 0, 0};
}

bool transfer(int socket, int platform, int application) {
    int descriptors[] = {platform, application};
    const size_t count = application >= 0 ? 2 : 1;
    char payload = 'L';
    iovec vector{&payload, 1};
    char control[CMSG_SPACE(sizeof(descriptors))]{};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    std::memcpy(CMSG_DATA(header), descriptors, count * sizeof(int));
    return sendmsg(socket, &message, MSG_NOSIGNAL) == 1;
}

int receive(int socket, int descriptors[2]) {
    char payload;
    iovec vector{&payload, 1};
    char control[CMSG_SPACE(2 * sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket, &message, 0) != 1 || payload != 'L') return 0;
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) return 0;
    const int count = static_cast<int>((header->cmsg_len - CMSG_LEN(0)) / sizeof(int));
    if (count < 1 || count > 2) return 0;
    std::memcpy(descriptors, CMSG_DATA(header), count * sizeof(int));
    return count;
}

struct ThreadProbe { int gate; long result; };
void* thread_probe(void* raw) {
    auto* probe = static_cast<ThreadProbe*>(raw);
    char ready;
    if (read(probe->gate, &ready, 1) != 1) { probe->result = -1; return nullptr; }
    probe->result = syscall(target_call, 0);
    return nullptr;
}
void sigsys_handler(int, siginfo_t* info, void*) { trapped = info->si_syscall == target_call && info->si_arch == AUDIT_ARCH_X86_64; }

void fixture_child(Mode mode, int socket, int output, const char* executable) {
    setsid();
    const int platform = install(target_call, SECCOMP_RET_USER_NOTIF, platform_flag | SECCOMP_FILTER_FLAG_NEW_LISTENER);
    if (platform < 0) report(output, {0, 0, errno, 10});
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) report(output, {0, 0, errno, 11});
    pthread_t thread{};
    int gate[2]{-1, -1};
    ThreadProbe probe{};
    if (mode == Mode::threads) {
        if (pipe(gate)) report(output, {0, 0, errno, 12});
        probe.gate = gate[0];
        if (pthread_create(&thread, nullptr, thread_probe, &probe)) report(output, {0, 0, errno, 13});
    }
    unsigned action = SECCOMP_RET_ALLOW;
    int number = -1;
    unsigned flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;
    if (mode == Mode::independent) { number = SYS_getuid; action = SECCOMP_RET_USER_NOTIF; }
    if (mode == Mode::overlap || mode == Mode::threads) { number = target_call; action = SECCOMP_RET_USER_NOTIF; }
    if (mode == Mode::deny) { number = target_call; action = SECCOMP_RET_ERRNO | EACCES; flags = 0; }
    if (mode == Mode::trap) {
        number = target_call; action = SECCOMP_RET_TRAP; flags = 0;
        struct sigaction handler{};
        handler.sa_sigaction = sigsys_handler;
        handler.sa_flags = SA_SIGINFO;
        if (sigaction(SIGSYS, &handler, nullptr)) report(output, {0, 0, errno, 14});
    }
    if (mode == Mode::threads) flags |= SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
    const int installed = install(number, action, flags);
    if (installed < 0) report(output, {0, 0, errno, 15});
    const int application = flags & SECCOMP_FILTER_FLAG_NEW_LISTENER ? installed : -1;
    if (!transfer(socket, platform, application)) report(output, {0, 0, errno, 16});
    close(platform);
    if (application >= 0) close(application);
    close(socket);
    if (mode == Mode::executed) {
        if (fcntl(output, F_SETFD, 0)) report(output, {0, 0, errno, 17});
        char descriptor[24];
        std::snprintf(descriptor, sizeof(descriptor), "%d", output);
        execl(executable, executable, "--exec-probe", descriptor, nullptr);
        report(output, {0, 0, errno, 18});
    }
    if (mode == Mode::forked) {
        pid_t child = static_cast<pid_t>(syscall(SYS_fork));
        if (child == 0) _exit(syscall(target_call, 0) == marker ? 0 : 1);
        int status = 0;
        const bool passed = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        report(output, {passed, status, 0, 0});
    }
    if (mode == Mode::threads) {
        if (write(gate[1], "R", 1) != 1) report(output, {0, 0, errno, 19});
        const long result = syscall(target_call, 0);
        pthread_join(thread, nullptr);
        report(output, {result == marker && probe.result == marker, static_cast<int>(result), 0, static_cast<int>(probe.result)});
    }
    errno = 0;
    const long result = syscall(target_call, 0);
    const int error = errno;
    bool passed = result == marker;
    if (mode == Mode::independent) passed &= syscall(SYS_getuid) == marker + 1;
    if (mode == Mode::deny) passed = result == -1 && error == EACCES;
    if (mode == Mode::trap) passed = trapped == 1;
    if (mode == Mode::addfd) {
        char buffer[64]{};
        passed = result >= 0 && read(static_cast<int>(result), buffer, sizeof(buffer)) == static_cast<ssize_t>(std::strlen(fd_payload)) && !std::strcmp(buffer, fd_payload);
        passed &= result >= 0 && (fcntl(static_cast<int>(result), F_GETFD) & FD_CLOEXEC);
        if (result >= 0) close(static_cast<int>(result));
    }
    report(output, {passed, static_cast<int>(result), error, static_cast<int>(trapped)});
}

Result fixture(const char* name, Mode mode, const char* executable) {
    int sockets[2], output[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) || pipe2(output, O_CLOEXEC)) return {name, false, 0, 0, errno};
    timeval timeout{5, 0};
    setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    pid_t child = fork();
    if (child == 0) { close(sockets[0]); close(output[0]); fixture_child(mode, sockets[1], output[1], executable); }
    close(sockets[1]); close(output[1]);
    if (child < 0) { close(sockets[0]); close(output[0]); return {name, false, 0, 0, errno}; }
    int listeners[2]{-1, -1};
    const int count = receive(sockets[0], listeners);
    close(sockets[0]);
    bool valid = count >= 1;
    int platform_events = 0, application_events = 0;
    std::unordered_map<unsigned, unsigned> continued;
    Observation observation{};
    bool observed = false, finished = false;
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
    while (count && std::chrono::steady_clock::now() < deadline) {
        pollfd descriptors[] = {{listeners[1], POLLIN, 0}, {listeners[0], POLLIN, 0}, {output[0], POLLIN, 0}};
        if (poll(descriptors, 3, 100) < 0 && errno != EINTR) { valid = false; break; }
        for (int index = 0; index < 2; index++) {
            if (!(descriptors[index].revents & POLLIN)) continue;
            seccomp_notif request{};
            const int listener = descriptors[index].fd;
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request)) { if (errno != EINTR && errno != ENOENT) valid = false; continue; }
            const bool application = index == 0;
            if (application) application_events++; else platform_events++;
            valid &= request.data.arch == AUDIT_ARCH_X86_64;
            valid &= request.data.nr == (application && mode == Mode::independent ? SYS_getuid : target_call);
            uint64_t id = request.id;
            valid &= ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
            seccomp_notif_resp response{};
            response.id = request.id;
            if (application && (mode == Mode::overlap || mode == Mode::threads)) {
                response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                continued[request.pid]++;
            } else {
                if (!application && (mode == Mode::overlap || mode == Mode::threads)) {
                    valid &= continued[request.pid] > 0;
                    if (continued[request.pid]) continued[request.pid]--;
                }
                response.val = application ? marker + 1 : marker;
            }
            if (mode == Mode::addfd && !application) {
                int source = static_cast<int>(syscall(SYS_memfd_create, "platform-notifier-fixture", MFD_CLOEXEC));
                bool injected = source >= 0 && write(source, fd_payload, std::strlen(fd_payload)) == static_cast<ssize_t>(std::strlen(fd_payload)) && lseek(source, 0, SEEK_SET) == 0;
                seccomp_notif_addfd add{};
                add.id = request.id; add.flags = SECCOMP_ADDFD_FLAG_SEND; add.srcfd = static_cast<unsigned>(source); add.newfd_flags = O_CLOEXEC;
                injected &= source >= 0 && ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add) >= 0;
                if (source >= 0) close(source);
                valid &= injected;
                if (injected) continue;
                response.error = -EIO;
            }
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) && errno != ENOENT) valid = false;
        }
        if (!observed && (descriptors[2].revents & POLLIN)) observed = read(output[0], &observation, sizeof(observation)) == sizeof(observation);
        if (waitpid(child, &status, WNOHANG) == child) { finished = true; break; }
    }
    if (!finished) { kill(-child, SIGKILL); kill(child, SIGKILL); waitpid(child, &status, 0); valid = false; }
    if (!observed) observed = read(output[0], &observation, sizeof(observation)) == sizeof(observation);
    close(output[0]);
    for (int listener : listeners) if (listener >= 0) close(listener);
    valid &= observed && observation.passed && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (mode == Mode::deny || mode == Mode::trap) valid &= platform_events == 0 && application_events == 0;
    else if (mode == Mode::threads) valid &= platform_events == 2 && application_events == 2;
    else if (mode == Mode::overlap || mode == Mode::independent) valid &= platform_events == 1 && application_events == 1;
    else valid &= platform_events >= 1 && application_events == 0;
    return {name, valid, platform_events, application_events, observation.error};
}
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 3 && !std::strcmp(argv[1], "--exec-probe")) {
        const long result = syscall(target_call, 0);
        report(std::atoi(argv[2]), {result == marker, static_cast<int>(result), errno, 0});
    }
    if (getuid() != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0) return 2;
    const bool baseline = argc == 2 && !std::strcmp(argv[1], "--baseline");
    const bool feature = argc == 2 && !std::strcmp(argv[1], "--feature");
    const Observation normal = capacity_child(false, false);
    const Observation unprivileged = capacity_child(false, true);
    const Observation platform = capacity_child(true, false);
    const bool supported = platform.passed;
    if (feature) return supported && normal.passed && unprivileged.passed ? 0 : 1;
    std::vector<Result> results = {{"standard_listener_capacity", normal.passed != 0, 0, 0, normal.error}, {"unprivileged_platform_flag_rejected", unprivileged.passed != 0 && unprivileged.extra == 2000, 0, 0, unprivileged.error}};
    if (supported) {
        results.push_back({"separate_listener_capacity", true, 0, 0, platform.error});
        results.push_back(metadata_introspection());
        char executable[4096]{};
        const ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
        if (length < 0) return 2;
        const std::pair<const char*, Mode> cases[] = {{"independent_targets",Mode::independent},{"overlap_continue_order",Mode::overlap},{"application_errno_precedes_platform",Mode::deny},{"application_trap_precedes_platform",Mode::trap},{"fork_inheritance",Mode::forked},{"thread_tsync",Mode::threads},{"exec_inheritance",Mode::executed},{"platform_atomic_fd_injection",Mode::addfd}};
        for (const auto& item : cases) results.push_back(fixture(item.first, item.second, executable));
    }
    size_t passed = 0;
    std::printf("{\"platform_domain_supported\":%s,\"platform_probe_errno\":%d,\"cases\":[", supported ? "true" : "false", supported ? 0 : platform.error);
    for (size_t index = 0; index < results.size(); index++) {
        const auto& result = results[index];
        passed += result.passed;
        std::printf("%s{\"name\":\"%s\",\"passed\":%s,\"platform_notifications\":%d,\"application_notifications\":%d,\"errno\":%d}", index ? "," : "", result.name, result.passed ? "true" : "false", result.platform_events, result.application_events, result.error);
    }
    std::printf("],\"passed\":%zu,\"failed\":%zu,\"unavailable\":%d}\n", passed, results.size() - passed, supported ? 0 : 10);
    return passed == results.size() && (supported || baseline) ? 0 : 1;
}
