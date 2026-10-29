#define main platform_contract_main
#include "../platform-seccomp-check.cpp"
#undef main
#include <sys/stat.h>

int main(int argc, char** argv) {
    // The contract re-executes itself while checking inherited filters.
    if (argc == 3 && !std::strcmp(argv[1], "--exec-probe")) {
        return platform_contract_main(argc, argv);
    }

    char context[128]{};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        read(fd, context, sizeof(context) - 1);
        close(fd);
        context[std::strcspn(context, "\n")] = '\0';
    }
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct capabilities[2]{};
    const int cap_result = static_cast<int>(syscall(SYS_capget, &header, capabilities));
    const uint64_t effective = capabilities[0].effective |
        (static_cast<uint64_t>(capabilities[1].effective) << 32);
    const int no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

    fd = open("/dev/device-lab-contract.json", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0 || fchmod(fd, 0644) < 0 || dup2(fd, STDOUT_FILENO) < 0) return 120;
    if (fd != STDOUT_FILENO) close(fd);
    char name[] = "device-lab-root-contract";
    char mode[] = "--require-platform";
    char* arguments[]{name, mode, nullptr};
    const int result = platform_contract_main(2, arguments);
    std::fflush(stdout);

    fd = open("/dev/device-lab-contract-meta.json", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0 || fchmod(fd, 0644) < 0) return 121;
    dprintf(fd,
        "{\"uid\":%u,\"euid\":%u,\"context\":\"%s\",\"no_new_privs\":%d,"
        "\"capget_result\":%d,\"effective_capabilities\":\"%016llx\",\"contract_exit_code\":%d}\n",
        getuid(), geteuid(), context, no_new_privs, cap_result,
        static_cast<unsigned long long>(effective), result);
    close(fd);
    return result;
}
