#pragma once
#include <android/log.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EXEC_PROBE_TAG "DeviceLabExecProbe"

static int exec_probe_libraries(struct dl_phdr_info* info, size_t size, void* value) {
    (void)size;
    unsigned* found = value;
    if (strstr(info->dlpi_name, "/libandroid_runtime.so")) *found |= 1;
    if (strstr(info->dlpi_name, "/libart.so")) *found |= 2;
    return 0;
}

static inline void log_exec_state(const char* stage) {
    char context[128] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        read(fd, context, sizeof(context) - 1);
        close(fd);
        context[strcspn(context, "\n")] = '\0';
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct capabilities[2] = {{0}, {0}};
    int cap_result = (int)syscall(SYS_capget, &header, capabilities);
    uint64_t effective = capabilities[0].effective | ((uint64_t)capabilities[1].effective << 32);
    uint64_t permitted = capabilities[0].permitted | ((uint64_t)capabilities[1].permitted << 32);
    uint64_t inheritable = capabilities[0].inheritable | ((uint64_t)capabilities[1].inheritable << 32);
    uint64_t bounding = 0, ambient = 0;
    int capability_errors = 0;
    for (unsigned cap = 0; cap <= CAP_LAST_CAP; ++cap) {
        int bound = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        int active = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
        if (bound == 1) bounding |= (uint64_t)1 << cap;
        if (active == 1) ambient |= (uint64_t)1 << cap;
        if (bound < 0 || active < 0) ++capability_errors;
    }
    gid_t groups[64];
    int group_count = getgroups(64, groups);
    char group_text[768];
    size_t position = 0;
    group_text[position++] = '[';
    for (int i = 0; i < group_count; ++i) {
        position += (size_t)snprintf(group_text + position, sizeof(group_text) - position,
                                   "%s%u", i ? "," : "", groups[i]);
    }
    group_text[position++] = ']';
    group_text[position] = '\0';
    unsigned libraries = 0;
    dl_iterate_phdr(exec_probe_libraries, &libraries);
    char command_line[4096];
    ssize_t command_size = -1;
    fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        command_size = read(fd, command_line, sizeof(command_line));
        close(fd);
    }
    uint64_t command_hash = UINT64_C(14695981039346656037);
    int argument_count = 0;
    for (ssize_t i = 0; i < command_size; ++i) {
        command_hash = (command_hash ^ (unsigned char)command_line[i]) * UINT64_C(1099511628211);
        if (command_line[i] == '\0') ++argument_count;
    }
    __android_log_print(ANDROID_LOG_INFO, EXEC_PROBE_TAG,
        "{\"stage\":\"%s\",\"pid\":%d,\"uid\":%u,\"euid\":%u,\"context\":\"%s\","
        "\"at_secure\":%lu,\"no_new_privs\":%d,\"capget_result\":%d,"
        "\"effective_capabilities\":\"%016llx\",\"permitted_capabilities\":\"%016llx\","
        "\"inheritable_capabilities\":\"%016llx\",\"bounding_capabilities\":\"%016llx\","
        "\"ambient_capabilities\":\"%016llx\",\"capability_query_errors\":%d,"
        "\"gid\":%u,\"egid\":%u,\"group_count\":%d,\"groups\":%s,"
        "\"runtime_library_visible\":%s,\"art_library_visible\":%s,"
        "\"command_line_size\":%zd,\"command_line_hash_fnv1a\":\"%016llx\","
        "\"argument_count\":%d,\"preload_present\":%s}",
        stage, getpid(), getuid(), geteuid(), context, getauxval(AT_SECURE),
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), cap_result,
        (unsigned long long)effective, (unsigned long long)permitted,
        (unsigned long long)inheritable, (unsigned long long)bounding,
        (unsigned long long)ambient, capability_errors,
        getgid(), getegid(), group_count, group_text,
        libraries & 1 ? "true" : "false", libraries & 2 ? "true" : "false",
        command_size, (unsigned long long)command_hash, argument_count,
        getenv("LD_PRELOAD") ? "true" : "false");
}
