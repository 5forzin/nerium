#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
int main(int argc, char** argv) {
    if (argc != 2) return 1;
    const int pid = atoi(argv[1]);
    errno = 0; const int handle = syscall(SYS_pidfd_open, pid, 0);
    printf("pidfd_open=%d errno=%d\n", handle, errno);
    errno = 0; const int fd = syscall(SYS_pidfd_getfd, handle, 0, 0);
    printf("pidfd_getfd=%d errno=%d\n", fd, errno);
    errno = 0; const long cmp = syscall(SYS_kcmp, pid, pid, 2, 0, 0);
    printf("kcmp_files=%ld errno=%d\n", cmp, errno);
    if (fd >= 0) close(fd);
    if (handle >= 0) close(handle);
    const int directory = open("/proc/self/map_files", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    errno = 0; const long invalid = syscall(SYS_getdents64, directory, nullptr, 512);
    const int saved = errno;
    printf("kernel_null_getdents=%ld errno=%d position=%lld\n", invalid, saved, (long long)lseek(directory, 0, SEEK_CUR));
    close(directory);
    return fd < 0 || cmp != 0;
}
