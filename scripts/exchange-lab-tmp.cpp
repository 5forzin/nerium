#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr const char* tmp_path = "/data/local/tmp";
constexpr const char* stage_path = "/data/local/device-lab-tmp-v12";
struct Xattr { std::string name; std::vector<char> value; };
struct Metadata { struct stat value; std::vector<Xattr> attributes; };
struct Entry { std::string name; ino_t inode; dev_t device; };

void require(bool value, const char* operation) {
    if (!value) throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

Metadata metadata(int fd) {
    Metadata result{};
    require(fstat(fd, &result.value) == 0, "fstat");
    char names[4096];
    ssize_t count = flistxattr(fd, names, sizeof(names));
    require(count >= 0, "flistxattr");
    for (ssize_t offset = 0; offset < count; offset += std::strlen(names + offset) + 1) {
        if (std::strcmp(names + offset, "security.selinux") && std::strcmp(names + offset, "security.sehash"))
            throw std::runtime_error(std::string("Unmodeled directory xattr: ") + (names + offset));
        char value[4096];
        ssize_t length = fgetxattr(fd, names + offset, value, sizeof(value));
        require(length > 0, "fgetxattr");
        result.attributes.push_back({names + offset, std::vector<char>(value, value + length)});
    }
    require(!result.attributes.empty(), "Directory SELinux attributes missing");
    return result;
}

void restore_metadata(int fd, const Metadata& saved) {
    require(fchown(fd, saved.value.st_uid, saved.value.st_gid) == 0, "fchown");
    require(fchmod(fd, saved.value.st_mode & 07777) == 0, "fchmod");
    auto current = metadata(fd);
    for (const auto& attribute : current.attributes) {
        bool retained = false;
        for (const auto& wanted : saved.attributes) retained |= attribute.name == wanted.name;
        if (!retained) require(fremovexattr(fd, attribute.name.c_str()) == 0, "fremovexattr");
    }
    for (const auto& attribute : saved.attributes)
        require(fsetxattr(fd, attribute.name.c_str(), attribute.value.data(), attribute.value.size(), 0) == 0, "fsetxattr");
    timespec times[] = {saved.value.st_atim, saved.value.st_mtim};
    require(futimens(fd, times) == 0, "futimens");
}

std::vector<Entry> entries(int fd) {
    int copy = dup(fd);
    require(copy >= 0, "dup");
    DIR* directory = fdopendir(copy);
    require(directory != nullptr, "fdopendir");
    rewinddir(directory);
    std::vector<Entry> result;
    errno = 0;
    while (dirent* item = readdir(directory)) {
        if (!std::strcmp(item->d_name, ".") || !std::strcmp(item->d_name, "..")) continue;
        struct stat value{};
        if (fstatat(fd, item->d_name, &value, AT_SYMLINK_NOFOLLOW) != 0) {
            closedir(directory);
            throw std::runtime_error("Directory changed while enumerating");
        }
        result.push_back({item->d_name, value.st_ino, value.st_dev});
        errno = 0;
    }
    int error = errno;
    closedir(directory);
    require(error == 0, "readdir");
    return result;
}

void exchange() {
    require(syscall(SYS_renameat2, AT_FDCWD, tmp_path, AT_FDCWD, stage_path, 2) == 0, "RENAME_EXCHANGE");
}
}

int main(int argc, char** argv) {
    bool apply = argc == 2 && !std::strcmp(argv[1], "--apply");
    bool restore = argc == 2 && !std::strcmp(argv[1], "--restore");
    bool check = argc == 2 && !std::strcmp(argv[1], "--check");
    if (!apply && !restore && !check) return 2;
    char qemu[PROP_VALUE_MAX]{};
    __system_property_get("ro.kernel.qemu", qemu);
    if (getuid() != 0 || std::strcmp(qemu, "1")) return 2;
    int old_tmp = open(tmp_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int old_stage = open(stage_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool exchanged = false;
    size_t moved = 0;
    std::vector<Entry> children;
    Metadata tmp{}, stage{};
    try {
        require(old_tmp >= 0 && old_stage >= 0, "Open fixed lab directories");
        tmp = metadata(old_tmp);
        stage = metadata(old_stage);
        require(tmp.value.st_dev == stage.value.st_dev, "Different filesystems");
        struct statfs filesystem{};
        require(fstatfs(old_tmp, &filesystem) == 0 && filesystem.f_type == 0xef53, "Expected ext4");
        require(tmp.value.st_uid == 2000 && tmp.value.st_gid == 2000 && (tmp.value.st_mode & 07777) == 0771, "Unexpected tmp ownership/mode");
        require(stage.value.st_uid == 0 && stage.value.st_gid == 0 && (stage.value.st_mode & 07777) == 0700, "Unexpected stage ownership/mode");
        require(tmp.value.st_ino == (restore ? 1000 : 65538) && stage.value.st_ino == (restore ? 65538 : 1000), "Unexpected directory identities");
        require(entries(old_stage).empty(), "Staging directory must be empty");
        children = entries(old_tmp);
        if (check) {
            std::printf("{\"tmp_inode\":%llu,\"stage_inode\":%llu,\"entries\":%zu,\"stage_empty\":true,\"modified\":false}\n",
                static_cast<unsigned long long>(tmp.value.st_ino), static_cast<unsigned long long>(stage.value.st_ino), children.size());
            return 0;
        }
        // Child renames preserve their actual inodes, labels and contents.
        exchange();
        exchanged = true;
        for (const auto& child : children) {
            require(renameat(old_tmp, child.name.c_str(), old_stage, child.name.c_str()) == 0, "Move tmp entry");
            moved++;
            struct stat after{};
            require(fstatat(old_stage, child.name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == 0 && after.st_ino == child.inode && after.st_dev == child.device, "Child inode changed");
        }
        require(entries(old_tmp).empty(), "Concurrent tmp directory mutation");
        restore_metadata(old_stage, tmp);
        restore_metadata(old_tmp, stage);
        require(fsync(old_tmp) == 0 && fsync(old_stage) == 0 && syscall(SYS_syncfs, old_tmp) == 0, "Flush filesystem exchange");
        struct stat final_tmp{}, final_stage{};
        require(lstat(tmp_path, &final_tmp) == 0 && lstat(stage_path, &final_stage) == 0 && final_tmp.st_ino == stage.value.st_ino && final_stage.st_ino == tmp.value.st_ino, "Validate canonical paths");
        std::printf("{\"operation\":\"%s\",\"tmp_inode_before\":%llu,\"tmp_inode_after\":%llu,\"stage_inode_after\":%llu,\"entries_preserved\":%zu,\"child_inodes_preserved\":true,\"stage_empty\":true,\"data_copied\":false}\n",
            restore ? "restore" : "apply", static_cast<unsigned long long>(tmp.value.st_ino), static_cast<unsigned long long>(final_tmp.st_ino),
            static_cast<unsigned long long>(final_stage.st_ino), children.size());
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        if (exchanged) {
            try {
                while (moved) {
                    const auto& child = children[--moved];
                    require(renameat(old_stage, child.name.c_str(), old_tmp, child.name.c_str()) == 0, "Rollback tmp entry");
                }
                restore_metadata(old_tmp, tmp);
                restore_metadata(old_stage, stage);
                exchange();
                syscall(SYS_syncfs, old_tmp);
                std::fprintf(stderr, "Original directory layout restored.\n");
            } catch (const std::exception& rollback) {
                std::fprintf(stderr, "Rollback failed: %s\n", rollback.what());
            }
        }
        return 1;
    }
}
