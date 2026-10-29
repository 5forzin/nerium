#include <jni.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

// Keep the instruction in this ELF: libc syscall/open/read hooks cannot intercept it.
__attribute__((noinline)) long raw(long number, long a = 0, long b = 0, long c = 0,
                                 long d = 0, long e = 0, long f = 0) {
    register long r10 asm("r10") = d;
    register long r8 asm("r8") = e;
    register long r9 asm("r9") = f;
    long result;
    asm volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c),
                 "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}
long ptr(const void* value) { return reinterpret_cast<long>(value); }
std::string quote(const std::string& value) {
    std::string result = "\"";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') result += '\\';
        if (ch >= 32) result += static_cast<char>(ch);
    }
    return result + "\"";
}

struct Collector {
    std::vector<std::string> checks;
    void add(const std::string& id, const std::string& status, const std::string& detail = "") {
        checks.push_back("{\"id\":" + quote(id) + ",\"status\":" + quote(status) + ",\"detail\":" + quote(detail) + "}");
    }
    void control(const std::string& id, bool passed, const std::string& detail = "") {
        add(id, passed ? "clear" : "detected", detail);
    }
    void unavailable(const std::string& id, long result) { add(id, "unavailable", "result=" + std::to_string(result)); }
};
bool artifact(const std::string& text) {
    for (const char* marker : {"libndk_translation", "libhoudini", "dev.androidlab.module-", "proc-broker-", " /proc/cpuinfo ", "/adb/modules/device_lab_cpu/"})
        if (text.find(marker) != std::string::npos) return true;
    return false;
}
std::string read_all(long fd, long& result) {
    std::string text;
    char buffer[8192];
    while ((result = raw(SYS_read, fd, ptr(buffer), sizeof(buffer))) > 0) {
        text.append(buffer, static_cast<size_t>(result));
        if (text.size() > 8 * 1024 * 1024) { result = -EFBIG; break; }
    }
    return text;
}
void inspect(Collector& report, const std::string& id, long fd) {
    if (fd < 0) { report.unavailable(id, fd); return; }
    long result = 0;
    const std::string text = read_all(fd, result);
    raw(SYS_close, fd);
    if (result < 0 || text.empty()) report.unavailable(id, result);
    else report.control(id, !artifact(text), "bytes=" + std::to_string(text.size()));
}
// Unknown Android seccomp calls can raise SIGSYS. Isolate capability checks.
long capability(bool extended_open) {
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) != 0) return -errno;
    const pid_t child = fork();
    if (child == 0) {
        raw(SYS_close, descriptors[0]);
        struct open_how how{};
        how.flags = O_RDONLY | O_CLOEXEC;
        struct statx info{};
        const long result = extended_open ? raw(SYS_openat2, AT_FDCWD, ptr("/proc/self/maps"), ptr(&how), sizeof(how))
                : raw(SYS_statx, AT_FDCWD, ptr("/proc/self/maps"), 0, STATX_BASIC_STATS | STATX_MNT_ID, ptr(&info));
        if (extended_open && result >= 0) raw(SYS_close, result);
        raw(SYS_write, descriptors[1], ptr(&result), sizeof(result));
        raw(SYS_exit_group, 0);
        __builtin_unreachable();
    }
    close(descriptors[1]);
    long result = -EIO;
    if (child > 0) {
        const ssize_t count = read(descriptors[0], &result, sizeof(result));
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        if (WIFSIGNALED(status)) result = -10000 - WTERMSIG(status);
        else if (count != sizeof(result)) result = -EIO;
    }
    close(descriptors[0]);
    return result;
}
unsigned long long number(const std::string& text, const char* key) {
    const size_t offset = text.find(std::string(key) + ":");
    if (offset == std::string::npos) return ~0ULL;
    return std::strtoull(text.c_str() + offset + std::strlen(key) + 1, nullptr, 10);
}

extern "C" JNIEXPORT jstring JNICALL Java_dev_androidlab_procprobe_MainActivity_collectNative(JNIEnv* env, jclass) {
    Collector report;
    const long can_open = capability(true), can_stat = capability(false);
    if (can_open < 0) report.unavailable("capability.openat2", can_open); else report.control("capability.openat2", true);
    if (can_stat < 0) report.unavailable("capability.statx", can_stat); else report.control("capability.statx", true);
    for (const std::string view : {"maps", "smaps", "mountinfo", "mounts"}) {
        const std::string path = "/proc/self/" + view;
        for (const auto& flag : std::vector<std::pair<std::string, int>>{{"nofollow", O_NOFOLLOW}, {"noctty", O_NOCTTY}, {"noatime", O_NOATIME}})
            inspect(report, view + ".open." + flag.first, raw(SYS_openat, AT_FDCWD, ptr(path.c_str()), O_RDONLY | O_CLOEXEC | flag.second));
        if (can_open >= 0) {
            struct open_how how{}; how.flags = O_RDONLY | O_CLOEXEC;
            inspect(report, view + ".openat2", raw(SYS_openat2, AT_FDCWD, ptr(path.c_str()), ptr(&how), sizeof(how)));
        }
        const long fd = raw(SYS_openat, AT_FDCWD, ptr(path.c_str()), O_RDONLY | O_CLOEXEC);
        if (fd < 0) { report.unavailable(view + ".source", fd); continue; }
        const std::string alias = "/proc/self/fd/" + std::to_string(fd);
        struct stat expected{}, actual{};
        raw(SYS_newfstatat, AT_FDCWD, ptr(path.c_str()), ptr(&expected), 0);
        const long stat_result = raw(SYS_stat, ptr(alias.c_str()), ptr(&actual));
        report.control(view + ".legacy_stat", stat_result == 0 && actual.st_dev == expected.st_dev
                && actual.st_ino == expected.st_ino && actual.st_size == expected.st_size, "size=" + std::to_string(actual.st_size));
        struct statfs fs{};
        const long fs_result = raw(SYS_statfs, ptr(alias.c_str()), ptr(&fs));
        report.control(view + ".statfs_alias", fs_result == 0 && fs.f_type == 0x9fa0, "type=" + std::to_string(fs.f_type));
        struct statx expected_x{}, actual_x{};
        if (can_stat >= 0) {
            const unsigned mask = STATX_BASIC_STATS | STATX_MNT_ID;
            raw(SYS_statx, AT_FDCWD, ptr(path.c_str()), 0, mask, ptr(&expected_x));
            for (bool empty : {false, true}) {
                const long result = raw(SYS_statx, empty ? fd : AT_FDCWD, ptr(empty ? "" : alias.c_str()), empty ? AT_EMPTY_PATH : 0, mask, ptr(&actual_x));
                report.control(view + (empty ? ".statx_empty" : ".statx_alias"), result == 0
                        && actual_x.stx_ino == expected_x.stx_ino && actual_x.stx_size == expected_x.stx_size
                        && actual_x.stx_dev_minor == expected_x.stx_dev_minor && actual_x.stx_mnt_id == expected_x.stx_mnt_id,
                        "mnt_id=" + std::to_string(actual_x.stx_mnt_id) + ";expected=" + std::to_string(expected_x.stx_mnt_id));
            }
            report.control(view + ".statx_null", raw(SYS_statx, fd, ptr(""), AT_EMPTY_PATH, mask, 0) == -EFAULT);
            report.control(view + ".statx_reserved_mask", raw(SYS_statx, fd, ptr(""), AT_EMPTY_PATH, 0x80000000U, ptr(&actual_x)) == -EINVAL);
            const long page = raw(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page > 0) {
                report.control(view + ".statx_readonly", raw(SYS_statx, fd, ptr(""), AT_EMPTY_PATH, mask, page) == -EFAULT
                        && *reinterpret_cast<const unsigned char*>(page) == 0);
                raw(SYS_munmap, page, 4096);
            } else report.unavailable(view + ".statx_readonly", page);
        }
        char first[64]{}, second[64]{};
        const long count = raw(SYS_read, fd, ptr(first), sizeof(first));
        const std::string info_path = "/proc/self/fdinfo/" + std::to_string(fd);
        const long info = raw(SYS_openat, AT_FDCWD, ptr(info_path.c_str()), O_RDONLY | O_CLOEXEC);
        if (info >= 0) {
            struct statfs info_fs{};
            report.control(view + ".fdinfo_procfs", raw(SYS_fstatfs, info, ptr(&info_fs)) == 0 && info_fs.f_type == 0x9fa0);
            long result = 0; const std::string text = read_all(info, result); raw(SYS_close, info);
            report.control(view + ".fdinfo_inode", result == 0 && number(text, "ino") == expected.st_ino, text);
            report.control(view + ".fdinfo_position", result == 0 && number(text, "pos") == static_cast<unsigned long long>(count));
            if (can_stat >= 0) report.control(view + ".fdinfo_mount", result == 0 && number(text, "mnt_id") == expected_x.stx_mnt_id);
        } else report.unavailable(view + ".fdinfo", info);
        const long address = raw(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        report.control(view + ".mmap_denied", address == -ENODEV, "result=" + std::to_string(address));
        if (address > 0) raw(SYS_munmap, address, 4096);
        report.control(view + ".mmap_zero", raw(SYS_mmap, 0, 0, PROT_READ, MAP_PRIVATE, fd, 0) == -EINVAL);
        report.control(view + ".mmap_offset", raw(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, fd, 1) == -EINVAL);
        report.control(view + ".statfs_null", raw(SYS_statfs, ptr(alias.c_str()), 0) == -EFAULT);
        report.control(view + ".nofollow_link", raw(SYS_openat, AT_FDCWD, ptr(alias.c_str()), O_RDONLY | O_CLOEXEC | O_NOFOLLOW) == -ELOOP);
        iovec parts[]{{second, 17}, {second + 17, sizeof(second) - 17}};
        raw(SYS_lseek, fd, 0, SEEK_SET);
        report.control(view + ".readv", raw(SYS_readv, fd, ptr(parts), 2) == count && std::memcmp(first, second, sizeof(first)) == 0);
        std::memset(second, 0, sizeof(second));
        report.control(view + ".preadv", raw(SYS_preadv, fd, ptr(parts), 2, 0, 0) == count && std::memcmp(first, second, sizeof(first)) == 0);
        const long copy = raw(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 0);
        report.control(view + ".dup_offset", copy >= 0 && raw(SYS_lseek, copy, 13, SEEK_SET) == 13 && raw(SYS_lseek, fd, 0, SEEK_CUR) == 13);
        if (copy >= 0) raw(SYS_close, copy);
        raw(SYS_close, fd);
    }
    inspect(report, "proc.numa_maps", raw(SYS_openat, AT_FDCWD, ptr("/proc/self/numa_maps"), O_RDONLY | O_CLOEXEC));
    const long directory = raw(SYS_openat, AT_FDCWD, ptr("/proc/self/map_files"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory >= 0) {
        struct Entry { uint64_t ino; int64_t offset; unsigned short length; unsigned char type; char name[1]; };
        alignas(8) char buffer[16384];
        raw(SYS_lseek, directory, 0, SEEK_SET);
        const long invalid = raw(SYS_getdents64, directory, 0, 512);
        const long position = raw(SYS_lseek, directory, 0, SEEK_CUR);
        report.control("map_files.null_buffer", invalid == -EFAULT && position == 0, "result=" + std::to_string(invalid) + ";position=" + std::to_string(position));
        raw(SYS_lseek, directory, 0, SEEK_SET);
        report.control("map_files.small_buffer", raw(SYS_getdents64, directory, ptr(buffer), 1) == -EINVAL
                && raw(SYS_lseek, directory, 0, SEEK_CUR) == 0);
        const long first_count = raw(SYS_getdents64, directory, ptr(buffer), 512);
        const std::string first_name = first_count > 0 ? reinterpret_cast<const Entry*>(buffer)->name : "";
        raw(SYS_lseek, directory, 0, SEEK_SET);
        const long repeated_count = raw(SYS_getdents64, directory, ptr(buffer), 512);
        const std::string repeated_name = repeated_count > 0 ? reinterpret_cast<const Entry*>(buffer)->name : "";
        report.control("map_files.rewind", !first_name.empty() && first_name == repeated_name);
        raw(SYS_lseek, directory, 0, SEEK_SET);
        size_t seen = 0, readable = 0, found = 0;
        std::string evidence;
        long count;
        while ((count = raw(SYS_getdents64, directory, ptr(buffer), sizeof(buffer))) > 0) {
            size_t offset = 0;
            while (offset < static_cast<size_t>(count)) {
                const auto* entry = reinterpret_cast<const Entry*>(buffer + offset);
                if (entry->length < 20 || offset + entry->length > static_cast<size_t>(count)) break;
                if (entry->name[0] != '.') {
                    ++seen; char target[4096];
                    const long size = raw(SYS_readlinkat, directory, ptr(entry->name), ptr(target), sizeof(target));
                    if (size > 0) {
                        ++readable; const std::string value(target, static_cast<size_t>(size));
                        if (artifact(value)) { ++found; if (evidence.empty()) evidence = value; }
                    }
                }
                offset += entry->length;
            }
        }
        raw(SYS_close, directory);
        const std::string detail = "entries=" + std::to_string(seen) + ";readable=" + std::to_string(readable) + ";artifacts=" + std::to_string(found) + ";" + evidence;
        if (count < 0 || readable == 0) report.add("proc.map_files", "unavailable", detail);
        else report.control("proc.map_files", found == 0, detail);
    } else report.unavailable("proc.map_files", directory);
    std::string json = "{\"abi\":\"x86_64\",\"transport\":\"inline-syscall\",\"checks\":[";
    for (size_t i = 0; i < report.checks.size(); ++i) { if (i) json += ','; json += report.checks[i]; }
    return env->NewStringUTF((json + "]}").c_str());
}
