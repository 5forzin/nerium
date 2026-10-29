#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>

bool context(const char* node, const char* value) {
    const int fd = open(node, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const ssize_t count = write(fd, value, std::strlen(value) + 1);
    const int error = errno;
    close(fd);
    errno = error;
    return count == static_cast<ssize_t>(std::strlen(value) + 1);
}

int main() {
    if (getuid() != 0) return 2;
    if (!context("/proc/self/attr/sockcreate", "u:r:zygote:s0")) return 3;
    const int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    context("/proc/self/attr/sockcreate", "");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const int length = std::snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "device_lab_ipc_check_%u", getpid());
    const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + length + 1);
    if (server < 0 || bind(server, reinterpret_cast<sockaddr*>(&address), size) || listen(server, 1)) return 4;
    const pid_t child = fork();
    if (child == 0) {
        close(server);
        if (!context("/proc/self/attr/current", "u:r:zygote:s0")) _exit(100 + errno);
        const int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (client < 0) _exit(errno);
        const int result = connect(client, reinterpret_cast<sockaddr*>(&address), size);
        const int error = result == 0 ? 0 : errno;
        close(client);
        _exit(error);
    }
    int status = 0;
    const bool collected = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status);
    close(server);
    const int result = collected ? WEXITSTATUS(status) : 255;
    std::printf("{\"zygote_abstract_socket_connected\":%s,\"child_status\":%d,\"policy_modified\":false}\n", result == 0 ? "true" : "false", result);
    return result == 0 ? 0 : 1;
}
