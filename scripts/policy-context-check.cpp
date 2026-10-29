#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>

int validate(const char* context) {
    const int fd = open("/sys/fs/selinux/context", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const ssize_t written = write(fd, context, std::strlen(context) + 1);
    const int error = errno;
    close(fd);
    errno = error;
    return written == static_cast<ssize_t>(std::strlen(context) + 1) ? 0 : -1;
}

int main(int argc, char** argv) {
    const bool observe = argc == 2 && std::strcmp(argv[1], "--observe") == 0;
    const int enforce = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    char value = '\0';
    const bool available = enforce >= 0 && read(enforce, &value, 1) == 1;
    if (enforce >= 0) close(enforce);
    if (!available) {
        std::puts("{\"available\":false,\"reason\":\"Root selinuxfs enforcement read unavailable\"}");
        return 2;
    }
    struct Case { const char* name; const char* context; bool expected_valid; };
    const Case cases[] = {
        {"stock_zygote_control", "u:r:zygote:s0", true},
        {"malformed_control", "device_lab_invalid_context", false},
        {"magisk_domain_absent", "u:r:magisk:s0", false},
        {"magisk_file_type_absent", "u:object_r:magisk_file:s0", false},
    };
    const int mode = value == '1' ? 1 : 0;
    int passed = mode == 1 ? 1 : 0;
    bool controls = true;
    std::printf("{\"available\":true,\"uid\":%u,\"enforcing\":%s,\"cases\":[", getuid(), mode == 1 ? "true" : "false");
    for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        errno = 0;
        const int first = validate(cases[index].context);
        const int error = first == 0 ? 0 : errno;
        errno = 0;
        const int second = validate(cases[index].context);
        const int second_error = second == 0 ? 0 : errno;
        const bool stable = first == second && error == second_error;
        const bool success = stable && (cases[index].expected_valid ? first == 0 : first == -1 && error == EINVAL);
        passed += success ? 1 : 0;
        if (index < 2) controls &= success;
        std::printf("%s{\"name\":\"%s\",\"context_valid\":%s,\"errno\":%d,\"stable\":%s,\"passed\":%s}",
                    index ? "," : "", cases[index].name, first == 0 ? "true" : "false", error,
                    stable ? "true" : "false", success ? "true" : "false");
    }
    std::printf("],\"passed\":%d,\"failed\":%d,\"controls_passed\":%s}\n", passed, 5 - passed, controls ? "true" : "false");
    return mode == 1 && controls && (observe || passed == 5) ? 0 : 1;
}
