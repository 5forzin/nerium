#include "profile.hpp"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {
std::string property_area(const prop_info* info) {
    FILE* maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return {};
    char* line = nullptr;
    size_t capacity = 0;
    std::string result;
    while (getline(&line, &capacity, maps) >= 0) {
        unsigned long start, finish;
        char path[4096];
        if (std::sscanf(line, "%lx-%lx %*s %*s %*s %*s %4095s", &start, &finish, path) != 3) continue;
        const auto address = reinterpret_cast<uintptr_t>(info);
        if (address >= start && address < finish && std::strncmp(path, "/dev/__properties__/", 20) == 0) {
            result = path;
            break;
        }
    }
    free(line);
    fclose(maps);
    return result;
}

int write_all(int fd, const char* data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        const ssize_t count = write(fd, data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return count < 0 ? errno : EIO;
        offset += static_cast<size_t>(count);
    }
    return 0;
}

int clone_area(const std::string& path) {
    const int source = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (source < 0) return errno;
    std::string temporary = std::string(device_lab::profile_directory) + "/property.XXXXXX";
    const int destination = mkstemp(temporary.data());
    if (destination < 0) { const int result = errno; close(source); return result; }
    constexpr char context[] = "u:object_r:system_file:s0";
    int result = 0;
    if (fchmod(destination, 0644) != 0 || fsetxattr(destination, "security.selinux", context, sizeof(context), 0) != 0) result = errno;
    char buffer[4096];
    ssize_t count = 0;
    while (result == 0 && (count = read(source, buffer, sizeof(buffer))) > 0) {
        result = write_all(destination, buffer, static_cast<size_t>(count));
    }
    if (result == 0 && count < 0) result = errno;
    if (result == 0 && mount(temporary.c_str(), path.c_str(), nullptr, MS_BIND, nullptr) != 0) result = errno;
    unlink(temporary.c_str());
    close(destination);
    close(source);
    return result;
}
}

// Called only by the root worker after entering a verified private app namespace.
int install_property_profile() {
    constexpr char standalone[] = "/data/misc/device-lab/resetprop";
    struct stat helper{};
    const bool standalone_ready = lstat(standalone, &helper) == 0;
    if (standalone_ready && (!S_ISREG(helper.st_mode) || helper.st_uid != 0 || (helper.st_mode & 0777) != 0700)) return EPERM;
    if (!standalone_ready && errno != ENOENT) return errno;
    std::vector<std::string> areas{"/dev/__properties__/properties_serial"};
    std::string profile;
    for (const auto& property : device_lab::properties) {
        const prop_info* info = __system_property_find(property.name);
        if (info == nullptr) {
            if (property.value[0] == '\0') continue;
            return ENOENT;
        }
        const std::string area = property_area(info);
        if (area.empty()) return ENOENT;
        if (std::find(areas.begin(), areas.end(), area) == areas.end()) areas.push_back(area);
        profile += std::string(property.name) + "=" + property.value + "\n";
    }

    std::vector<std::string> mounted;
    int result = 0;
    for (const auto& area : areas) {
        result = clone_area(area);
        if (result != 0) break;
        mounted.push_back(area);
    }
    std::string temporary = std::string(device_lab::profile_directory) + "/profile.XXXXXX";
    int fd = -1;
    if (result == 0) {
        fd = mkstemp(temporary.data());
        if (fd < 0) result = errno;
        else { result = write_all(fd, profile.data(), profile.size()); close(fd); }
    }
    if (result == 0) {
        const pid_t writer = fork();
        if (writer == 0) {
            // Exec discards inherited mappings, so resetprop opens only the private clones.
            if (standalone_ready)
                execl(standalone, "resetprop", "-n", "-f", temporary.c_str(), nullptr);
            else
                execl("/system/bin/magisk", "magisk", "resetprop", "-n", "-f", temporary.c_str(), nullptr);
            _exit(127);
        }
        if (writer < 0) result = errno;
        else {
            int status = 0;
            pid_t waited;
            do { waited = waitpid(writer, &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) result = EIO;
        }
    }
    if (fd >= 0) unlink(temporary.c_str());
    if (result == 0) {
        for (const auto& area : mounted) {
            if (mount(nullptr, area.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr) != 0) {
                result = errno;
                break;
            }
        }
    }
    if (result != 0) {
        for (auto area = mounted.rbegin(); area != mounted.rend(); ++area) umount2(area->c_str(), MNT_DETACH);
    }
    return result;
}

int refresh_property_mappings() {
    struct Mapping { uintptr_t start; size_t length; off_t offset; std::string path; };
    std::vector<Mapping> mappings;
    FILE* maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return errno;
    char* line = nullptr;
    size_t capacity = 0;
    while (getline(&line, &capacity, maps) >= 0) {
        unsigned long start, finish, offset, inode;
        unsigned int major, minor;
        char permissions[5], path[4096];
        if (std::sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %4095s", &start, &finish, permissions,
                        &offset, &major, &minor, &inode, path) != 8) continue;
        if (std::strncmp(path, "/dev/__properties__/", 20) != 0) continue;
        struct stat current{};
        if (stat(path, &current) != 0) continue;
        if (current.st_ino == inode && current.st_dev == makedev(major, minor)) continue;
        if (permissions[0] != 'r' || permissions[1] != '-' || permissions[2] != '-') continue;
        mappings.push_back({start, finish - start, static_cast<off_t>(offset), path});
    }
    free(line);
    fclose(maps);
    // Keep the virtual addresses stable for Bionic's inherited property-area pointers.
    for (const auto& mapping : mappings) {
        const int fd = open(mapping.path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        void* result = mmap(reinterpret_cast<void*>(mapping.start), mapping.length, PROT_READ,
                            MAP_SHARED | MAP_FIXED, fd, mapping.offset);
        const int error = errno;
        close(fd);
        if (result == MAP_FAILED) return error;
    }
    return 0;
}
