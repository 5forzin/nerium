#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
int main() {
    struct open_how how = {0}; how.flags = O_RDONLY | O_CLOEXEC;
    errno = 0; long fd = syscall(SYS_openat2, AT_FDCWD, "/proc/self/maps", &how, sizeof(how)); int open_error = errno;
    if (fd >= 0) close(fd);
    errno = 0; long small = syscall(SYS_openat2, AT_FDCWD, "/proc/self/maps", &how, 0); int small_error = errno;
    errno = 0; long numa = syscall(SYS_openat, AT_FDCWD, "/proc/self/numa_maps", O_RDONLY); int numa_error = errno;
    if (numa >= 0) close(numa);
    int mode = 0; errno = 0; long policy = syscall(SYS_get_mempolicy, &mode, NULL, 0, NULL, 0); int policy_error = errno;
    printf("{\"openat2\":%ld,\"openat2_errno\":%d,\"short_how\":%ld,\"short_how_errno\":%d,\"numa_maps\":%ld,\"numa_errno\":%d,\"get_mempolicy\":%ld,\"get_mempolicy_errno\":%d}\n", fd, open_error, small, small_error, numa, numa_error, policy, policy_error);
    return fd < 0;
}
