#define _GNU_SOURCE
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/kcmp.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum operation { SELF_READ, MAPS_READ, MEM_READ, REMOTE_READ, FILE_TABLE, GET_FD, ACTION_QUERY, SIZE_QUERY };
enum stage { START, IDENTITY, SELF_ACCESS, SUBJECT_PREPARE, SUBJECT_READY, PROC_OPEN, DATA_READ, PIDFD_OPEN, PIDFD_GETFD, KCMP_CALL, QUERY_CALL, FINISHED };
static const char* const operation_names[] = {"self_process_vm_readv", "proc_maps", "proc_mem", "process_vm_readv", "kcmp_files", "pidfd_getfd", "seccomp_action_avail", "seccomp_notif_sizes"};
static const char payload[] = "device-lab boundary payload";

struct identity {
    unsigned uid, euid, gid, egid, fsuid, fsgid;
    int group_count;
    gid_t groups[64];
    int dumpable, no_new_privs, seccomp, filters, context_available, capabilities_available;
    uint64_t capabilities[5];
    char context[128];
};

struct observation {
    atomic_int ready, finish, stage;
    int operation, requested_dumpable, parent_pid, runner_pid, subject_pid, subject_fd, runner_identity_complete;
    int completed, prepare_errno, wait_status, subject_wait_status;
    int alive_before_checked, alive_before, alive_after_checked, alive_after;
    struct identity runner, subject;
    int attempted, returned, error, matched, open_attempted, open_returned, open_error, exit_signal;
    int64_t result, open_result;
    uint64_t value, expected;
    unsigned notif_size, response_size, data_size;
};

static int read_text(const char* path, char* output, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count = read(fd, output, size - 1);
    int saved = errno;
    close(fd);
    errno = saved;
    if (count < 0) return -1;
    output[count] = 0;
    return (int)count;
}

static long status_number(const char* status, const char* key, int base) {
    const char* value = strstr(status, key);
    return value ? strtol(value + strlen(key), NULL, base) : -1;
}

static unsigned fourth_id(const char* status, const char* key) {
    const char* value = strstr(status, key);
    if (!value) return UINT32_MAX;
    char* next = (char*)value + strlen(key);
    for (unsigned i = 0; i < 3; ++i) strtoul(next, &next, 10);
    return (unsigned)strtoul(next, NULL, 10);
}

static void identity(struct identity* value) {
    value->uid = getuid(); value->euid = geteuid();
    value->gid = getgid(); value->egid = getegid();
    value->group_count = getgroups(64, value->groups);
    value->dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    value->no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    value->seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    value->context_available = read_text("/proc/thread-self/attr/current", value->context, sizeof(value->context)) > 0;
    value->context[strcspn(value->context, "\n")] = 0;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    value->capabilities_available = syscall(SYS_capget, &header, caps) == 0;
    value->capabilities[0] = caps[0].effective | ((uint64_t)caps[1].effective << 32);
    value->capabilities[1] = caps[0].permitted | ((uint64_t)caps[1].permitted << 32);
    value->capabilities[2] = caps[0].inheritable | ((uint64_t)caps[1].inheritable << 32);
    char status[4096] = {0};
    if (read_text("/proc/thread-self/status", status, sizeof(status)) > 0) {
        value->fsuid = fourth_id(status, "Uid:");
        value->fsgid = fourth_id(status, "Gid:");
        const char* bounding = strstr(status, "CapBnd:");
        const char* ambient = strstr(status, "CapAmb:");
        if (bounding && ambient) {
            value->capabilities[3] = strtoull(bounding + 7, NULL, 16);
            value->capabilities[4] = strtoull(ambient + 7, NULL, 16);
        } else value->capabilities_available = 0;
        value->filters = (int)status_number(status, "Seccomp_filters:", 10);
    } else { value->filters = -1; value->capabilities_available = 0; value->fsuid = value->fsgid = UINT32_MAX; }
}

static int64_t milliseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void wait_briefly(void) {
    struct timespec delay = {0, 1000000};
    nanosleep(&delay, NULL);
}

static pid_t wait_child(pid_t pid, int* status) {
    pid_t result;
    do { result = waitpid(pid, status, 0); } while (result < 0 && errno == EINTR);
    return result;
}

static void subject(struct observation* value, volatile uint64_t* token) {
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    if (getppid() != value->runner_pid) _exit(90);
    if (prctl(PR_SET_DUMPABLE, value->requested_dumpable, 0, 0, 0)) {
        value->prepare_errno = errno;
        _exit(91);
    }
    *token = value->expected;
    if (value->operation == GET_FD) {
        value->subject_fd = (int)syscall(SYS_memfd_create, "boundary-probe", MFD_CLOEXEC);
        if (value->subject_fd < 0 || write(value->subject_fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) {
            value->prepare_errno = errno;
            _exit(92);
        }
    }
    identity(&value->subject);
    atomic_store_explicit(&value->ready, 1, memory_order_release);
    int64_t deadline = milliseconds() + 4000;
    while (!atomic_load_explicit(&value->finish, memory_order_acquire) && milliseconds() < deadline) wait_briefly();
    if (value->subject_fd >= 0) close(value->subject_fd);
    _exit(0);
}

static void observe_return(struct observation* value, long result) {
    int error = result < 0 ? errno : 0;
    value->result = result;
    value->error = error;
    value->returned = 1;
}

static void runner(struct observation* value) {
    struct sigaction action = {0};
    action.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &action, NULL);
    alarm(7);
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    if (getppid() != value->parent_pid) _exit(90);
    value->runner_pid = getpid();
    atomic_store(&value->stage, IDENTITY);
    identity(&value->runner);
    value->runner_identity_complete = 1;
    volatile uint64_t token = UINT64_C(0x1122334455667788);
    uint64_t destination = 0;
    struct iovec local = {&destination, sizeof(destination)};
    struct iovec remote = {(void*)&token, sizeof(token)};
    if (value->operation == SELF_READ) {
        if (prctl(PR_SET_DUMPABLE, value->requested_dumpable, 0, 0, 0)) { value->prepare_errno = errno; _exit(93); }
        identity(&value->runner);
        atomic_store(&value->stage, SELF_ACCESS);
        errno = 0;
        value->attempted = 1;
        observe_return(value, syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0));
        value->value = destination;
        value->expected = token;
        value->matched = value->result == (int64_t)sizeof(token) && destination == token;
    } else if (value->operation == ACTION_QUERY || value->operation == SIZE_QUERY) {
        atomic_store(&value->stage, QUERY_CALL);
        uint32_t requested = SECCOMP_RET_USER_NOTIF;
        struct seccomp_notif_sizes sizes = {0};
        errno = 0;
        value->attempted = 1;
        observe_return(value, value->operation == ACTION_QUERY ? syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &requested) : syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes));
        value->notif_size = sizes.seccomp_notif;
        value->response_size = sizes.seccomp_notif_resp;
        value->data_size = sizes.seccomp_data;
    } else {
        atomic_store(&value->stage, SUBJECT_PREPARE);
        pid_t pid = fork();
        if (pid < 0) { value->prepare_errno = errno; _exit(94); }
        if (pid == 0) subject(value, &token);
        value->subject_pid = pid;
        int64_t deadline = milliseconds() + 2000;
        while (!atomic_load_explicit(&value->ready, memory_order_acquire) && milliseconds() < deadline) wait_briefly();
        if (!atomic_load(&value->ready)) { kill(pid, SIGKILL); wait_child(pid, NULL); _exit(95); }
        atomic_store(&value->stage, SUBJECT_READY);
        int early_status = 0;
        value->alive_before_checked = 1;
        value->alive_before = waitpid(pid, &early_status, WNOHANG) == 0;
        if (!value->alive_before) _exit(98);
        if (value->operation == REMOTE_READ) {
            atomic_store(&value->stage, DATA_READ);
            errno = 0;
            value->attempted = 1;
            observe_return(value, syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0));
            value->value = destination;
            value->matched = value->result == (int64_t)sizeof(token) && destination == value->expected;
        } else if (value->operation == FILE_TABLE) {
            atomic_store(&value->stage, KCMP_CALL);
            errno = 0;
            value->attempted = 1;
            observe_return(value, syscall(SYS_kcmp, getpid(), pid, KCMP_FILES, 0, 0));
        } else if (value->operation == GET_FD) {
            atomic_store(&value->stage, PIDFD_OPEN);
            errno = 0;
            value->open_attempted = 1;
            int descriptor = (int)syscall(SYS_pidfd_open, pid, 0);
            value->open_returned = 1; value->open_result = descriptor; value->open_error = descriptor < 0 ? errno : 0;
            if (descriptor >= 0) {
                atomic_store(&value->stage, PIDFD_GETFD);
                errno = 0;
                value->attempted = 1;
                int copy = (int)syscall(SYS_pidfd_getfd, descriptor, value->subject_fd, 0);
                observe_return(value, copy);
                if (copy >= 0) {
                    char data[sizeof(payload)] = {0};
                    ssize_t count = pread(copy, data, sizeof(data), 0);
                    value->matched = count == (ssize_t)sizeof(payload) && memcmp(data, payload, sizeof(payload)) == 0;
                    close(copy);
                }
                close(descriptor);
            }
        } else {
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/%s", pid, value->operation == MAPS_READ ? "maps" : "mem");
            atomic_store(&value->stage, PROC_OPEN);
            errno = 0;
            value->open_attempted = 1;
            int descriptor = open(path, O_RDONLY | O_CLOEXEC);
            value->open_returned = 1; value->open_result = descriptor; value->open_error = descriptor < 0 ? errno : 0;
            if (descriptor >= 0) {
                atomic_store(&value->stage, DATA_READ);
                char maps[64] = {0};
                errno = 0;
                value->attempted = 1;
                observe_return(value, value->operation == MAPS_READ ? read(descriptor, maps, sizeof(maps)) : pread(descriptor, &destination, sizeof(destination), (off_t)(uintptr_t)&token));
                value->value = destination;
                value->matched = value->operation == MAPS_READ ? value->result > 0 : value->result == (int64_t)sizeof(token) && destination == value->expected;
                close(descriptor);
            }
        }
        value->alive_after_checked = 1;
        value->alive_after = waitpid(pid, &early_status, WNOHANG) == 0;
        if (!value->alive_after) _exit(99);
        atomic_store_explicit(&value->finish, 1, memory_order_release);
        int status = 0;
        if (wait_child(pid, &status) != pid) { value->prepare_errno = errno; _exit(96); }
        value->subject_wait_status = status;
        if (!WIFEXITED(status) || WEXITSTATUS(status)) _exit(97);
    }
    atomic_store(&value->stage, FINISHED);
    value->completed = 1;
    _exit(0);
}

static void append(char* output, size_t size, size_t* length, const char* format, ...) {
    if (*length >= size) return;
    va_list args;
    va_start(args, format);
    int count = vsnprintf(output + *length, size - *length, format, args);
    va_end(args);
    if (count >= 0) *length += (size_t)count;
}

static void append_identity(char* output, size_t size, size_t* length, const struct identity* value) {
    append(output, size, length, "{\"uid\":%u,\"euid\":%u,\"gid\":%u,\"egid\":%u,\"fsuid\":%u,\"fsgid\":%u,\"dumpable\":%d,\"no_new_privs\":%d,\"seccomp\":%d,\"seccomp_filters\":%d,\"context_available\":%s,\"context\":\"%s\",\"capabilities_available\":%s,\"capabilities\":[", value->uid, value->euid, value->gid, value->egid, value->fsuid, value->fsgid, value->dumpable, value->no_new_privs, value->seccomp, value->filters, value->context_available ? "true" : "false", value->context, value->capabilities_available ? "true" : "false");
    for (unsigned i = 0; i < 5; ++i) append(output, size, length, "%s\"%016" PRIx64 "\"", i ? "," : "", value->capabilities[i]);
    append(output, size, length, "],\"groups\":");
    if (value->group_count < 0) append(output, size, length, "null");
    else {
        append(output, size, length, "[");
        for (int i = 0; i < value->group_count; ++i) append(output, size, length, "%s%u", i ? "," : "", value->groups[i]);
        append(output, size, length, "]");
    }
    append(output, size, length, "}");
}

JNIEXPORT jstring JNICALL Java_dev_androidlab_boundaryprobe_MainActivity_collectNative(JNIEnv* env, jclass type) {
    (void)type;
    struct identity before = {0}, after = {0};
    identity(&before);
    struct observation* values = mmap(NULL, sizeof(struct observation) * 14, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (values == MAP_FAILED) return (*env)->NewStringUTF(env, "{\"schema_version\":1,\"error\":\"control mapping failed\"}");
    int index = 0;
    for (int operation = SELF_READ; operation <= SIZE_QUERY; ++operation) {
        int rounds = operation <= GET_FD ? 2 : 1;
        for (int mode = 0; mode < rounds; ++mode) {
            struct observation* value = &values[index++];
            value->operation = operation; value->requested_dumpable = mode;
            value->parent_pid = getpid();
            value->subject_fd = -1; value->expected = UINT64_C(0xaabbccdd11223300) + (unsigned)mode;
            pid_t pid = fork();
            if (pid == 0) runner(value);
            if (pid < 0) { value->prepare_errno = errno; continue; }
            int status = 0;
            if (wait_child(pid, &status) != pid) { value->prepare_errno = errno; kill(pid, SIGKILL); wait_child(pid, NULL); }
            else { value->wait_status = status; if (WIFSIGNALED(status)) value->exit_signal = WTERMSIG(status); }
        }
    }
    identity(&after);
    char* output = malloc(40000);
    if (!output) { munmap(values, sizeof(struct observation) * 14); return (*env)->NewStringUTF(env, "{\"schema_version\":1,\"error\":\"report allocation failed\"}"); }
    size_t length = 0;
    append(output, 40000, &length, "{\"schema_version\":1,\"scope\":\"read-only queries against this APK's own child processes; no filter installation or policy changes\",\"process_id\":%d,\"before\":", getpid());
    append_identity(output, 40000, &length, &before);
    append(output, 40000, &length, ",\"after\":");
    append_identity(output, 40000, &length, &after);
    append(output, 40000, &length, ",\"observations\":[");
    for (int i = 0; i < index; ++i) {
        const struct observation* value = &values[i];
        char result_text[32] = "null", open_text[32] = "null", sizes_text[64] = "null";
        char error_text[16] = "null", open_error_text[16] = "null";
        if (value->returned) snprintf(result_text, sizeof(result_text), "%" PRId64, value->result);
        if (value->returned) snprintf(error_text, sizeof(error_text), "%d", value->error);
        if (value->open_returned) snprintf(open_text, sizeof(open_text), "%" PRId64, value->open_result);
        if (value->open_returned) snprintf(open_error_text, sizeof(open_error_text), "%d", value->open_error);
        if (value->operation == SIZE_QUERY && value->returned && value->result == 0) snprintf(sizes_text, sizeof(sizes_text), "[%u,%u,%u]", value->notif_size, value->response_size, value->data_size);
        append(output, 40000, &length, "%s{\"operation\":\"%s\",\"requested_dumpable\":%d,\"runner_pid\":%d,\"subject_pid\":%d,\"completed\":%s,\"last_stage\":%d,\"prepare_errno\":%d,\"runner_wait_status\":%d,\"subject_wait_status\":%d,\"exit_signal\":%d,\"attempted\":%s,\"returned\":%s,\"return\":%s,\"errno\":%s,\"matched\":%s,\"open_attempted\":%s,\"open_returned\":%s,\"open_return\":%s,\"open_errno\":%s,\"value\":\"%016" PRIx64 "\",\"expected\":\"%016" PRIx64 "\",\"notification_sizes\":%s,\"runner\":", i ? "," : "", operation_names[value->operation], value->requested_dumpable, value->runner_pid, value->subject_pid, value->completed ? "true" : "false", atomic_load(&value->stage), value->prepare_errno, value->wait_status, value->subject_wait_status, value->exit_signal, value->attempted ? "true" : "false", value->returned ? "true" : "false", result_text, error_text, value->matched ? "true" : "false", value->open_attempted ? "true" : "false", value->open_returned ? "true" : "false", open_text, open_error_text, value->value, value->expected, sizes_text);
        if (value->runner_identity_complete) append_identity(output, 40000, &length, &value->runner);
        else append(output, 40000, &length, "null");
        append(output, 40000, &length, ",\"subject\":");
        if (atomic_load(&value->ready)) append_identity(output, 40000, &length, &value->subject);
        else append(output, 40000, &length, "null");
        append(output, 40000, &length, ",\"subject_alive_before\":%s,\"subject_alive_after\":%s", value->alive_before_checked ? (value->alive_before ? "true" : "false") : "null", value->alive_after_checked ? (value->alive_after ? "true" : "false") : "null");
        append(output, 40000, &length, "}");
    }
    append(output, 40000, &length, "]}");
    jstring result = (*env)->NewStringUTF(env, length < 40000 ? output : "{\"schema_version\":1,\"error\":\"report overflow\"}");
    free(output);
    munmap(values, sizeof(struct observation) * 14);
    return result;
}
