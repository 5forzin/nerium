#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>

int main() {
    // This standalone process installs only ALLOW filters and exits immediately.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("PR_SET_NO_NEW_PRIVS"); return 2; }
    sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    sock_fprog program{1, allow};
    errno = 0;
    const long first = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    const int first_error = first < 0 ? errno : 0;
    errno = 0;
    const long second = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    const int second_error = second < 0 ? errno : 0;
    std::printf("{\"first_listener_created\":%s,\"first_errno\":%d,\"second_listener_created\":%s,\"second_errno\":%d}\n",
                first >= 0 ? "true" : "false", first_error, second >= 0 ? "true" : "false", second_error);
    if (second >= 0) close(static_cast<int>(second));
    if (first >= 0) close(static_cast<int>(first));
    return first >= 0 && second_error == EBUSY ? 0 : 1;
}
