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
    void add(const std::string& id, const std::string& status, const std::string& detail) {
        checks.push_back("{\"id\":" + quote(id) + ",\"status\":" + quote(status) + ",\"detail\":" + quote(detail) + "}");
    }
    void control(const std::string& id, bool passed, const std::string& detail = "") {
        add(id, passed ? "clear" : "detected", detail);
    }
    void read_view(const std::string& id, int dir, const std::string& path, bool legacy = false, bool libc = false) {
        const long fd = libc ? openat(dir, path.c_str(), O_RDONLY | O_CLOEXEC)
                : legacy ? raw(SYS_open, ptr(path.c_str()), O_RDONLY | O_CLOEXEC)
                : raw(SYS_openat, dir, ptr(path.c_str()), O_RDONLY | O_CLOEXEC);
        if (fd < 0) { add(id, "unavailable", "open=" + std::to_string(fd)); return; }
        std::string text;
        char chunk[8192];
        long count;
        while ((count = raw(SYS_read, fd, ptr(chunk), sizeof(chunk))) > 0 && text.size() < 8 * 1024 * 1024)
            text.append(chunk, static_cast<size_t>(count));
        if (count < 0 || text.empty() || text.size() >= 8 * 1024 * 1024) {
            add(id, "unavailable", "read=" + std::to_string(count));
        } else {
            std::string evidence;
            for (const char* marker : {"/libndk_translation", "/libhoudini", "/dev.androidlab.module-", "/dev.androidlab.module/",
                                       " /proc/cpuinfo ", "/adb/modules/device_lab_cpu/"}) {
                const auto offset = text.find(marker);
                if (offset != std::string::npos) evidence += std::string(marker) + ";";
            }
            add(id, evidence.empty() ? "clear" : "detected", "bytes=" + std::to_string(text.size()) + ";" + evidence);
        }
        raw(SYS_close, fd);
    }
};

extern "C" JNIEXPORT jstring JNICALL Java_dev_androidlab_rawprobe_MainActivity_collectNative(JNIEnv* env, jclass) {
    Collector report;
    const std::string pid = std::to_string(raw(SYS_getpid));
    const std::string tid = std::to_string(raw(SYS_gettid));
    const std::string task = "/proc/self/task/" + tid;
    for (const std::string view : {"maps", "smaps", "mountinfo", "mounts"}) {
        for (const auto& entry : std::vector<std::pair<std::string, std::string>>{
                {"self", "/proc/self/"}, {"pid", "/proc/" + pid + "/"},
                {"tid", "/proc/" + tid + "/"}, {"thread_self", "/proc/thread-self/"},
                {"task", task + "/"}, {"normalized", "/proc//self/./task/" + tid + "/../" + tid + "/"}}) {
            report.read_view("raw." + view + "." + entry.first, AT_FDCWD, entry.second + view);
        }
        report.read_view("raw." + view + ".legacy_open", AT_FDCWD, "/proc/self/" + view, true);
        report.read_view("raw." + view + ".root_alias", AT_FDCWD, "/proc/self/root/proc/self/" + view);
        report.read_view("libc." + view + ".task", AT_FDCWD, task + "/" + view, false, true);
        const long dir = raw(SYS_openat, AT_FDCWD, ptr(task.c_str()), O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (dir >= 0) {
            report.read_view("raw." + view + ".dirfd", static_cast<int>(dir), "./" + view);
            raw(SYS_close, dir);
        } else report.add("raw." + view + ".dirfd", "unavailable", std::to_string(dir));
    }
    report.read_view("raw.mounts.proc_alias", AT_FDCWD, "/proc/mounts");
    for (const std::string view : {"maps", "mountinfo"}) {
        const std::string path = "/proc/self/" + view;
        const long fd = raw(SYS_openat, AT_FDCWD, ptr(path.c_str()), O_RDONLY | O_CLOEXEC);
        if (fd < 0) { report.add("control." + view, "unavailable", std::to_string(fd)); continue; }
        char first[64]{}, second[64]{}, link[4096]{};
        const long count = raw(SYS_read, fd, ptr(first), sizeof(first));
        report.control("control." + view + ".seek", count > 0 && raw(SYS_lseek, fd, 0, SEEK_SET) == 0
                && raw(SYS_read, fd, ptr(second), sizeof(second)) == count && std::memcmp(first, second, sizeof(first)) == 0);
        std::memset(second, 0, sizeof(second));
        report.control("control." + view + ".pread", raw(SYS_pread64, fd, ptr(second), sizeof(second), 0) == count
                && std::memcmp(first, second, sizeof(first)) == 0);
        report.control("control." + view + ".readonly", raw(SYS_write, fd, ptr("x"), 1) == -EBADF);
        report.control("control." + view + ".cloexec", raw(SYS_fcntl, fd, F_GETFD) == FD_CLOEXEC);
        struct statfs stats{};
        const long fs = raw(SYS_fstatfs, fd, ptr(&stats));
        report.control("control." + view + ".procfs", fs == 0 && stats.f_type == 0x9fa0, "type=" + std::to_string(stats.f_type));
        const std::string alias = "/proc/self/fd/" + std::to_string(fd);
        const long size = raw(SYS_readlinkat, AT_FDCWD, ptr(alias.c_str()), ptr(link), sizeof(link) - 1);
        const std::string target = size > 0 ? std::string(link, static_cast<size_t>(size)) : "";
        report.control("control." + view + ".fd_alias", target.find("/proc/") == 0 && target.size() >= view.size()
                && target.compare(target.size() - view.size(), view.size(), view) == 0, target);
        struct stat fd_stats{}, path_stats{};
        const long stat_result = raw(SYS_fstat, fd, ptr(&fd_stats));
        const long path_result = raw(SYS_newfstatat, AT_FDCWD, ptr(path.c_str()), ptr(&path_stats), 0);
        report.control("control." + view + ".fstat", stat_result == 0 && path_result == 0
                && fd_stats.st_size == path_stats.st_size && fd_stats.st_dev == path_stats.st_dev
                && fd_stats.st_ino == path_stats.st_ino && fd_stats.st_mode == path_stats.st_mode);
        report.control("control." + view + ".stat_empty", raw(SYS_newfstatat, fd, ptr(""), ptr(&fd_stats), AT_EMPTY_PATH) == 0
                && fd_stats.st_size == path_stats.st_size && fd_stats.st_dev == path_stats.st_dev);
        report.control("control." + view + ".stat_alias", raw(SYS_newfstatat, AT_FDCWD, ptr(alias.c_str()), ptr(&fd_stats), 0) == 0
                && fd_stats.st_size == path_stats.st_size && fd_stats.st_dev == path_stats.st_dev);
        report.control("control." + view + ".fstat_null", raw(SYS_fstat, fd, 0) == -EFAULT);
        report.control("control." + view + ".fstatfs_null", raw(SYS_fstatfs, fd, 0) == -EFAULT);
        report.control("control." + view + ".stat_null_path", raw(SYS_newfstatat, fd, 0, ptr(&fd_stats), AT_EMPTY_PATH) == -EFAULT);
        const std::string thread_alias = "/proc/thread-self/fd/" + std::to_string(fd);
        std::memset(link, 0, sizeof(link));
        const long thread_size = raw(SYS_readlinkat, AT_FDCWD, ptr(thread_alias.c_str()), ptr(link), sizeof(link) - 1);
        report.control("control." + view + ".thread_fd_alias", thread_size > 0 && std::string(link, static_cast<size_t>(thread_size)) == target);
        const long directory = raw(SYS_openat, AT_FDCWD, ptr("/proc/self/fd"), O_PATH | O_DIRECTORY | O_CLOEXEC);
        const std::string number = std::to_string(fd);
        std::memset(link, 0, sizeof(link));
        const long relative_size = raw(SYS_readlinkat, directory, ptr(number.c_str()), ptr(link), sizeof(link) - 1);
        report.control("control." + view + ".relative_fd_alias", relative_size > 0 && std::string(link, static_cast<size_t>(relative_size)) == target);
        if (directory >= 0) raw(SYS_close, directory);
        report.control("control." + view + ".readlink_zero", raw(SYS_readlinkat, AT_FDCWD, ptr(alias.c_str()), ptr(link), 0) == -EINVAL);
        report.control("control." + view + ".readlink_null", raw(SYS_readlinkat, AT_FDCWD, ptr(alias.c_str()), 0, sizeof(link)) == -EFAULT);
        const long page = raw(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page > 0) {
            report.control("control." + view + ".fstat_readonly", raw(SYS_fstat, fd, page) == -EFAULT
                    && *reinterpret_cast<const unsigned char*>(page) == 0);
            raw(SYS_munmap, page, 4096);
        } else report.add("control." + view + ".fstat_readonly", "unavailable", std::to_string(page));
        raw(SYS_close, fd);
    }
    report.control("control.invalid_dirfd", raw(SYS_openat, -1234, ptr("maps"), O_RDONLY) == -EBADF);
    report.control("control.missing", raw(SYS_openat, AT_FDCWD, ptr("/proc/self/missing-lab-file"), O_RDONLY) == -ENOENT);
    report.control("control.directory_flag", raw(SYS_openat, AT_FDCWD, ptr("/proc/self/maps"), O_RDONLY | O_DIRECTORY) == -ENOTDIR);
    report.control("control.null_path", raw(SYS_openat, AT_FDCWD, 0, O_RDONLY) == -EFAULT);
    std::string json = "{\"abi\":\"x86_64\",\"transport\":\"inline-syscall\",\"checks\":[";
    for (size_t i = 0; i < report.checks.size(); ++i) { if (i) json += ','; json += report.checks[i]; }
    json += "]}";
    return env->NewStringUTF(json.c_str());
}
