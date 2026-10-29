#include "uname_broker.hpp"
#include "proc_broker.hpp"

#include <android/log.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <limits>

namespace {
int copy_uname(const seccomp_notif& request, const struct utsname& value, int listener) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/mem", request.pid);
    const int memory = open(path, O_RDWR | O_CLOEXEC);
    if (memory < 0) return errno == EACCES || errno == EPERM ? EAGAIN : errno;
    std::snprintf(path, sizeof(path), "/proc/%u/maps", request.pid);
    FILE* maps = fopen(path, "re");
    if (maps == nullptr) { close(memory); return EAGAIN; }
    // Hold the original mm before validating the ID, so PID reuse cannot redirect writes.
    uint64_t id = request.id;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) != 0) { fclose(maps); close(memory); return ENOENT; }
    const uint64_t address = request.data.args[0];
    const bool fits = address <= static_cast<uint64_t>(std::numeric_limits<off_t>::max()) - sizeof(value);
    const uint64_t end = fits ? address + sizeof(value) : 0;
    uint64_t cursor = address;
    char line[4096];
    while (fits && cursor < end && fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long long start = 0, stop = 0;
        char permissions[5]{};
        if (std::sscanf(line, "%llx-%llx %4s", &start, &stop, permissions) == 3 && cursor >= start && cursor < stop) {
            if (permissions[1] != 'w') break;
            cursor = stop < end ? stop : end;
        }
    }
    fclose(maps);
    int error = EFAULT;
    if (fits && cursor == end) {
        const ssize_t written = pwrite(memory, &value, sizeof(value), static_cast<off_t>(address));
        if (written == static_cast<ssize_t>(sizeof(value))) error = 0;
        else if (written < 0 && (errno == EACCES || errno == EPERM)) error = EAGAIN;
    }
    close(memory);
    return error;
}
}

int install_uname_listener(bool proc_enabled, bool platform_supervisor) {
    // Install before dropping zygote privileges; no no_new_privs change is needed.
    sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_uname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_LD | BPF_W | BPF_IMM, proc_enabled ? 1U : 0U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstatfs, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_readlinkat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_readlink, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_stat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_statfs, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_statx, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getdents64, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[3])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, MAP_ANONYMOUS, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{static_cast<unsigned short>(sizeof(instructions) / sizeof(instructions[0])), instructions};
    constexpr unsigned platform_flag = 1U << 31;
    const unsigned flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | (platform_supervisor ? platform_flag : 0U);
    return static_cast<int>(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &program));
}

void serve_uname_listener(int listener, int client) {
    const int listener_copy = fcntl(listener, F_DUPFD_CLOEXEC, 10);
    const int client_copy = fcntl(client, F_DUPFD_CLOEXEC, 10);
    if (listener_copy < 0 || client_copy < 0 || dup2(listener_copy, 3) < 0 || dup2(client_copy, 4) < 0) {
        const int error = errno;
        send(client_copy >= 0 ? client_copy : client, &error, sizeof(error), MSG_NOSIGNAL);
        return;
    }
    // The detached worker must not keep the companion's listening/IPC descriptors alive.
    syscall(SYS_close_range, 5, ~0U, 0);
    listener = 3;
    client = 4;
    prctl(PR_SET_NAME, "lab-uname-broker");
    seccomp_notif_sizes sizes{};
    int status = syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0 ? 0 : errno;
    auto* request = status == 0 ? static_cast<seccomp_notif*>(std::calloc(1, sizes.seccomp_notif)) : nullptr;
    auto* response = status == 0 ? static_cast<seccomp_notif_resp*>(std::calloc(1, sizes.seccomp_notif_resp)) : nullptr;
    if (status == 0 && (request == nullptr || response == nullptr)) status = ENOMEM;
    uint64_t invalid_id = 0;
    if (status == 0 && ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &invalid_id) < 0 && errno != ENOENT) status = errno;
    struct utsname value{};
    if (status == 0 && uname(&value) != 0) status = errno;
    std::strcpy(value.machine, "aarch64");
    send(client, &status, sizeof(status), MSG_NOSIGNAL);
    close(client);
    if (status != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "DeviceLabUname", "broker initialization failed: %d", status);
        std::free(request);
        std::free(response);
        close(listener);
        return;
    }
    size_t handled = 0;
    pollfd pending{listener, POLLIN, 0};
    for (;;) {
        const int count = poll(&pending, 1, -1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (pending.revents & (POLLERR | POLLNVAL)) != 0) break;
        // Linux signals HUP when the last task using this filter has exited.
        if ((pending.revents & POLLIN) == 0) {
            if ((pending.revents & POLLHUP) != 0) break;
            continue;
        }
        std::memset(request, 0, sizes.seccomp_notif);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
            if (errno == EINTR || errno == ENOENT) continue;
            break;
        }
        std::memset(response, 0, sizes.seccomp_notif_resp);
        response->id = request->id;
        if (request->data.arch != AUDIT_ARCH_X86_64) {
            response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        } else if (request->data.nr != SYS_uname) {
            const int handled_proc = handle_proc_notification(*request, *response, listener);
            if (handled_proc == 2) { ++handled; continue; }
            if (handled_proc == 0) response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            else ++handled;
        } else if (notification_valid(listener, request->id)) {
            const int error = copy_uname(*request, value, listener);
            if (error == ENOENT) continue;
            if (error == EAGAIN) response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            else response->error = -error;
            ++handled;
        } else continue;
        int sent;
        do { sent = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response); } while (sent < 0 && errno == EINTR);
        if (sent != 0 && errno != ENOENT) break;
    }
    __android_log_print(ANDROID_LOG_INFO, "DeviceLabUname", "broker stopped: requests=%zu", handled);
    std::free(request);
    std::free(response);
    close(listener);
}
