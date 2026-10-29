#include <sys/types.h>
#include "vendor/zygisk.hpp"
#include "profile.hpp"
#include "uname_broker.hpp"
#include "policy_gate.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <sys/sysmacros.h>

int install_property_profile();
int refresh_property_mappings();

namespace {
struct Request { pid_t target; pid_t parent; int operation; };
struct ProfileReply { int status; int platform_supervisor; char runtime_apk[4096]; };

bool platform_supervisor_ready() {
    const int marker = open("/data/misc/device-lab/platform-supervisor-boot", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (marker < 0) return false;
    struct stat info{};
    const bool trusted = fstat(marker, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == 0 && (info.st_mode & 0777) == 0600;
    char qualified[64]{};
    const ssize_t expected = trusted ? read(marker, qualified, sizeof(qualified)) : -1;
    close(marker);
    if (expected <= 0 || expected >= static_cast<ssize_t>(sizeof(qualified))) return false;
    const int boot = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (boot < 0) return false;
    char current[64]{};
    const ssize_t length = read(boot, current, sizeof(current));
    close(boot);
    return expected == length && std::memcmp(qualified, current, static_cast<size_t>(expected)) == 0;
}

int repair_detached_null_descriptors() {
    DIR* descriptors = opendir("/proc/self/fd");
    if (!descriptors) return -errno;
    int repaired = 0;
    while (dirent* entry = readdir(descriptors)) {
        char* end = nullptr;
        const long number = std::strtol(entry->d_name, &end, 10);
        if (!end || *end || number < 0 || number == dirfd(descriptors)) continue;
        const int fd = static_cast<int>(number);
        struct stat info{};
        if (fstat(fd, &info) != 0 || !S_ISCHR(info.st_mode) || info.st_rdev != makedev(1, 3)) continue;
        char path[64], target[4096];
        std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        const ssize_t size = readlink(path, target, sizeof(target) - 1);
        if (size < 0) continue;
        target[size] = '\0';
        if (std::strcmp(target, "/null") != 0) continue;
        const int status = fcntl(fd, F_GETFL);
        const int descriptor = fcntl(fd, F_GETFD);
        if (status < 0 || descriptor < 0) continue;
        const int replacement = open("/dev/null", (status & (O_ACCMODE | O_APPEND | O_NONBLOCK)) | O_CLOEXEC);
        if (replacement < 0) continue;
        if (dup3(replacement, fd, (descriptor & FD_CLOEXEC) ? O_CLOEXEC : 0) >= 0) ++repaired;
        close(replacement);
    }
    closedir(descriptors);
    return repaired;
}

int unmount_app_zygote_overlays() {
    if (unshare(CLONE_NEWNS) != 0) return errno;
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) return errno;
    FILE* mounts = fopen("/proc/self/mountinfo", "re");
    if (!mounts) return errno;
    std::vector<std::string> targets;
    char* line = nullptr;
    size_t capacity = 0;
    while (getline(&line, &capacity, mounts) >= 0) {
        char root[4096]{}, point[4096]{}, source[4096]{};
        const char* separator = std::strstr(line, " - ");
        if (!separator || std::sscanf(line, "%*u %*u %*s %4095s %4095s", root, point) != 2
                || std::sscanf(separator + 3, "%*s %4095s", source) != 1) continue;
        if (std::strcmp(source, "magisk") == 0 || std::strcmp(source, "worker") == 0
                || std::strncmp(root, "/adb/modules/", 13) == 0) targets.emplace_back(point);
    }
    free(line);
    fclose(mounts);
    std::sort(targets.begin(), targets.end(), [](const auto& left, const auto& right) { return left.size() > right.size(); });
    int result = 0;
    for (const auto& target : targets) {
        if (umount2(target.c_str(), MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) result = errno;
    }
    return result;
}

int prepare_profile_directory() {
    if (mkdir(device_lab::profile_directory, 0755) != 0 && errno != EEXIST) return errno;
    const int directory = open(device_lab::profile_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return errno;
    struct stat info{};
    int result = fstat(directory, &info) == 0 && info.st_uid == 0 && (info.st_mode & 0777) == 0755 ? 0 : EPERM;
    constexpr char context[] = "u:object_r:system_file:s0";
    if (result == 0 && fsetxattr(directory, "security.selinux", context, sizeof(context), 0) != 0) result = errno;
    close(directory);
    return result;
}

int stage_runtime(char* destination, size_t capacity) {
    int config = open("/data/misc/device-lab/modules/device_lab_cpu/runtime-library", O_RDONLY | O_CLOEXEC);
    if (config < 0 && errno == ENOENT) {
        config = open("/data/adb/modules/device_lab_cpu/runtime-library", O_RDONLY | O_CLOEXEC);
    }
    if (config < 0) return 0;
    char text[4097];
    const ssize_t count = read(config, text, sizeof(text) - 1);
    close(config);
    if (count <= 0) return EIO;
    text[count] = '\0';
    const std::string source_path = std::string(text).substr(0, std::string(text).find("!/"));
    const int source = open(source_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0) return errno;
    struct stat info{};
    if (fstat(source, &info) != 0 || !S_ISREG(info.st_mode)) { close(source); return EINVAL; }
    const std::string staged = std::string(device_lab::profile_directory) + "/runtime-" + std::to_string(info.st_ino)
            + "-" + std::to_string(info.st_mtim.tv_sec) + "-" + std::to_string(info.st_mtim.tv_nsec) + ".apk";
    struct stat existing{};
    if (lstat(staged.c_str(), &existing) != 0) {
        std::string temporary = std::string(device_lab::profile_directory) + "/runtime.XXXXXX";
        const int output = mkstemp(temporary.data());
        if (output < 0) { const int error = errno; close(source); return error; }
        constexpr char context[] = "u:object_r:system_file:s0";
        int result = fchmod(output, 0644) == 0 && fsetxattr(output, "security.selinux", context, sizeof(context), 0) == 0 ? 0 : errno;
        char buffer[65536];
        ssize_t size = 0;
        while (result == 0 && (size = read(source, buffer, sizeof(buffer))) > 0) {
            ssize_t offset = 0;
            while (offset < size) {
                const ssize_t written = write(output, buffer + offset, static_cast<size_t>(size - offset));
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) { result = written < 0 ? errno : EIO; break; }
                offset += written;
            }
        }
        if (result == 0 && size < 0) result = errno;
        close(output);
        if (result == 0 && link(temporary.c_str(), staged.c_str()) != 0 && errno != EEXIST) result = errno;
        unlink(temporary.c_str());
        if (result != 0) { close(source); return result; }
        if (lstat(staged.c_str(), &existing) != 0) { close(source); return errno; }
    }
    close(source);
    if (!S_ISREG(existing.st_mode) || existing.st_uid != 0 || (existing.st_mode & 0777) != 0644 || existing.st_size != info.st_size) return EPERM;
    if (staged.size() >= capacity) return ENAMETOOLONG;
    std::memcpy(destination, staged.c_str(), staged.size() + 1);
    return 0;
}

int install_snapshot(const Request& request) {
    char target[64], parent[64];
    std::snprintf(target, sizeof(target), "/proc/%d/ns/mnt", request.target);
    std::snprintf(parent, sizeof(parent), "/proc/%d/ns/mnt", request.parent);
    struct stat target_stat{}, parent_stat{};
    if (stat(target, &target_stat) != 0 || stat(parent, &parent_stat) != 0) return errno;
    // Refuse a shared zygote namespace, even if unshare failed in the requester.
    if (target_stat.st_ino == parent_stat.st_ino) return EINVAL;
    const int space = open(target, O_RDONLY | O_CLOEXEC);
    if (space < 0) return errno;
    const int entered = setns(space, CLONE_NEWNS);
    const int saved = errno;
    close(space);
    if (entered != 0) return saved;
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) return errno;
    const int prepared = prepare_profile_directory();
    if (prepared != 0) return prepared;

    const long processors = sysconf(_SC_NPROCESSORS_ONLN);
    if (processors <= 0) return EINVAL;
    const char* fields = std::strchr(device_lab::arm64_cpuinfo, '\n') + 1;
    std::string text;
    for (long index = 0; index < processors; ++index) {
        text += "processor\t: " + std::to_string(index) + "\n";
        text += fields;
        text += '\n';
    }

    std::string temporary = std::string(device_lab::profile_directory) + "/cpuinfo.XXXXXX";
    const int fd = mkstemp(temporary.data());
    if (fd < 0) return errno;
    // proc_cpuinfo cannot associate with the data filesystem. Keep SELinux enforcing.
    constexpr char context[] = "u:object_r:system_file:s0";
    int result = 0;
    if (fchmod(fd, 0444) != 0 || fsetxattr(fd, "security.selinux", context, sizeof(context), 0) != 0) result = errno;
    size_t written = 0;
    while (result == 0 && written < text.size()) {
        const ssize_t size = write(fd, text.data() + written, text.size() - written);
        if (size <= 0) result = size < 0 ? errno : EIO;
        else written += static_cast<size_t>(size);
    }
    if (result == 0 && mount(temporary.c_str(), "/proc/cpuinfo", nullptr, MS_BIND, nullptr) != 0) result = errno;
    if (result == 0 && mount(nullptr, "/proc/cpuinfo", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr) != 0) {
        result = errno;
        umount2("/proc/cpuinfo", MNT_DETACH);
    }
    unlink(temporary.c_str());
    close(fd);
    return result == 0 ? install_property_profile() : result;
}

void companion(int socket) {
    Request request{};
    char control[CMSG_SPACE(sizeof(int))]{};
    iovec data{&request, sizeof(request)};
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket, &message, MSG_WAITALL | MSG_CMSG_CLOEXEC) != sizeof(request)) return;
    int listener = -1;
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)))
            std::memcpy(&listener, CMSG_DATA(header), sizeof(listener));
    }
    if (request.operation == 1) {
        int result = listener < 0 ? EINVAL : 0;
        const pid_t worker = result == 0 ? fork() : -1;
        if (worker == 0) {
            // Detach the broker so the companion can accept the next app request.
            const pid_t broker = fork();
            if (broker == 0) {
                serve_uname_listener(listener, socket);
                _exit(0);
            }
            if (broker < 0) { result = errno; send(socket, &result, sizeof(result), MSG_NOSIGNAL); }
            _exit(broker < 0 ? 1 : 0);
        }
        if (listener >= 0) close(listener);
        if (worker < 0) {
            if (result == 0) result = errno;
            send(socket, &result, sizeof(result), MSG_NOSIGNAL);
        } else while (waitpid(worker, nullptr, 0) < 0 && errno == EINTR) {}
        return;
    }
    if (listener >= 0) close(listener);
    if (request.operation != 0) return;
    // A child enters the app namespace; the companion daemon keeps its own namespace.
    const pid_t worker = fork();
    if (worker == 0) {
        ProfileReply reply{};
        reply.status = install_snapshot(request);
        if (reply.status == 0) reply.status = stage_runtime(reply.runtime_apk, sizeof(reply.runtime_apk));
        if (reply.status == 0) reply.platform_supervisor = platform_supervisor_ready() ? 1 : 0;
        send(socket, &reply, sizeof(reply), MSG_NOSIGNAL);
        _exit(reply.status == 0 ? 0 : 1);
    }
    if (worker > 0) {
        while (waitpid(worker, nullptr, 0) < 0 && errno == EINTR) {}
    }
}

class CpuNamespace : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        const char* name = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (name == nullptr) return;
        const std::string process(name);
        const bool detector = std::strcmp(name, "com.reveny.emulator.detection.sample") == 0;
        bool scoped = std::strcmp(name, "dev.androidlab.probe") == 0 || detector;
        env_->ReleaseStringUTFChars(args->nice_name, name);
        const int directory = api_->getModuleDir();
        if (directory < 0) return;
        const int scope_fd = openat(directory, "scope", O_RDONLY | O_CLOEXEC);
        if (scope_fd >= 0) {
            char scope[4097];
            const ssize_t size = read(scope_fd, scope, sizeof(scope) - 1);
            close(scope_fd);
            scoped = false;
            if (size > 0) {
                scope[size] = '\0';
                const std::string packages(scope);
                size_t start = 0;
                while (start < packages.size()) {
                    const size_t end = packages.find('\n', start);
                    const std::string package = packages.substr(start, end == std::string::npos ? end : end - start);
                    if (!package.empty() && (process == package || process == package + "_zygote"
                            || process.compare(0, package.size() + 1, package + ":") == 0)) scoped = true;
                    if (end == std::string::npos) break;
                    start = end + 1;
                }
            }
        }
        if (!scoped) { close(directory); return; }
        const int restrict_proc = openat(directory, "restrict-isolated-proc-enabled", O_RDONLY | O_CLOEXEC);
        if (restrict_proc >= 0) {
            close(restrict_proc);
            const int app_id = args->uid % 100000;
            if (app_id >= 99000 && app_id <= 99999) {
                std::vector<jint> groups;
                if (args->gids) {
                    const jsize count = env_->GetArrayLength(args->gids);
                    groups.resize(static_cast<size_t>(count));
                    env_->GetIntArrayRegion(args->gids, 0, count, groups.data());
                } else {
                    const int count = getgroups(0, nullptr);
                    if (count > 0) {
                        std::vector<gid_t> inherited(static_cast<size_t>(count));
                        if (getgroups(count, inherited.data()) == count) groups.assign(inherited.begin(), inherited.end());
                    }
                }
                const auto end = std::remove(groups.begin(), groups.end(), 3009);
                if (end != groups.end()) {
                    groups.erase(end, groups.end());
                    jintArray restricted = env_->NewIntArray(static_cast<jsize>(groups.size()));
                    if (restricted) {
                        if (!groups.empty()) env_->SetIntArrayRegion(restricted, 0, static_cast<jsize>(groups.size()), groups.data());
                        args->gids = restricted;
                        __android_log_print(ANDROID_LOG_INFO, "DeviceLabNamespace", "isolated READPROC grant removed uid=%d pid=%d", args->uid, getpid());
                    }
                }
            }
        }
        if (args->is_child_zygote && *args->is_child_zygote) {
            app_zygote_ = true;
            const int enabled = openat(directory, "enabled", O_RDONLY | O_CLOEXEC);
            close(directory);
            if (enabled >= 0) {
                close(enabled);
                api_->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
                const int result = unmount_app_zygote_overlays();
                __android_log_print(result == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                                    "DeviceLabNamespace", "app zygote private unmount status=%d pid=%d", result, getpid());
            }
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        const int arm_scope = openat(directory, "runtime-arm-scope", O_RDONLY | O_CLOEXEC);
        if (arm_scope >= 0) {
            char text[4097];
            const ssize_t size = read(arm_scope, text, sizeof(text) - 1);
            close(arm_scope);
            if (size > 0) {
                text[size] = '\0';
                const std::string packages = std::string("\n") + text;
                const std::string base = process.substr(0, process.find(':'));
                if (packages.find("\n" + base + "\n") != std::string::npos) setenv("DEVICE_LAB_ARM_GUEST", "1", 1);
            }
        }
        const int runtime_scope = openat(directory, "runtime-scope", O_RDONLY | O_CLOEXEC);
        if (runtime_scope >= 0) {
            char buffer[4097];
            const ssize_t size = read(runtime_scope, buffer, sizeof(buffer) - 1);
            close(runtime_scope);
            if (size > 0) {
                buffer[size] = '\0';
                const std::string packages(buffer);
                size_t start = 0;
                while (start < packages.size()) {
                    const size_t end = packages.find('\n', start);
                    const std::string package = packages.substr(start, end == std::string::npos ? end : end - start);
                    if (!package.empty() && (process == package || process.compare(0, package.size() + 1, package + ":") == 0)) {
                        const int profile = openat(directory, "runtime-library", O_RDONLY | O_CLOEXEC);
                        if (profile >= 0) {
                            char path[4097];
                            const ssize_t length = read(profile, path, sizeof(path) - 1);
                            close(profile);
                            if (length > 0) {
                                path[length] = '\0';
                                runtime_library_ = path;
                            }
                        }
                    }
                    if (end == std::string::npos) break;
                    start = end + 1;
                }
            }
        }
        const int enabled = openat(directory, "enabled", O_RDONLY | O_CLOEXEC);
        const int uname_enabled = openat(directory, "uname-enabled", O_RDONLY | O_CLOEXEC);
        const bool broker_enabled = uname_enabled >= 0;
        if (uname_enabled >= 0) close(uname_enabled);
        const int proc_enabled = openat(directory, "proc-enabled", O_RDONLY | O_CLOEXEC);
        const bool proc_broker_enabled = proc_enabled >= 0;
        if (proc_enabled >= 0) close(proc_enabled);
        const int openat2_enabled = openat(directory, "openat2-enabled", O_RDONLY | O_CLOEXEC);
        const bool policy_enabled = openat2_enabled >= 0;
        if (openat2_enabled >= 0) close(openat2_enabled);
        if (detector) {
            const int detector_enabled = openat(directory, "detector-enabled", O_RDONLY | O_CLOEXEC);
            if (detector_enabled < 0) {
                if (enabled >= 0) close(enabled);
                close(directory);
                return;
            }
            close(detector_enabled);
        }
        close(directory);
        if (enabled < 0) return;
        close(enabled);
        int result = 0;
        if (unshare(CLONE_NEWNS) != 0) result = errno;
        else {
            const int socket = api_->connectCompanion();
            if (socket < 0) result = ECONNREFUSED;
            else {
                timeval timeout{3, 0};
                setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                const Request request{getpid(), getppid(), 0};
                ProfileReply reply{};
                if (send(socket, &request, sizeof(request), MSG_NOSIGNAL) != sizeof(request)
                        || recv(socket, &reply, sizeof(reply), MSG_WAITALL) != sizeof(reply)) result = EIO;
                else { result = reply.status; staged_apk_ = reply.runtime_apk; platform_supervisor_ = reply.platform_supervisor == 1; }
                close(socket);
            }
        }
        __android_log_print(result == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                            "DeviceLabNamespace", "profile mount status=%d pid=%d", result, getpid());
        configured_ = result == 0;
        if (configured_ && !runtime_library_.empty()) {
            const std::string apk = runtime_library_.substr(0, runtime_library_.find("!/"));
            jclass path_loader = env_->FindClass("dalvik/system/PathClassLoader");
            jclass class_loader = env_->FindClass("java/lang/ClassLoader");
            jclass runtime = env_->FindClass("java/lang/Runtime");
            jmethodID constructor = env_->GetMethodID(path_loader, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
            jmethodID system_loader = env_->GetStaticMethodID(class_loader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
            jmethodID load_class = env_->GetMethodID(class_loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
            jmethodID load = env_->GetStaticMethodID(runtime, "nativeLoad", "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;");
            jstring apk_path = env_->NewStringUTF(staged_apk_.c_str());
            jstring search = env_->NewStringUTF((staged_apk_ + "!/lib/x86_64").c_str());
            jobject parent = env_->CallStaticObjectMethod(class_loader, system_loader);
            jobject loader = env_->NewObject(path_loader, constructor, apk_path, search, parent);
            jstring class_name = env_->NewStringUTF("dev.androidlab.module.RuntimeProfile");
            auto helper = static_cast<jclass>(env_->CallObjectMethod(loader, load_class, class_name));
            if (helper && !env_->ExceptionCheck()) {
                jstring library = env_->NewStringUTF((staged_apk_ + "!/lib/x86_64/libruntimeprofile.so").c_str());
                setenv("DEVICE_LAB_PREPARE_RUNTIME", "1", 1);
                auto error = static_cast<jstring>(env_->CallStaticObjectMethod(runtime, load, library, loader, helper));
                unsetenv("DEVICE_LAB_PREPARE_RUNTIME");
                if (!error && !env_->ExceptionCheck()) {
                    jmethodID prepare = env_->GetStaticMethodID(helper, "prepare", "(JLjava/lang/String;)Z");
                    jstring original_apk = env_->NewStringUTF(apk.c_str());
                    if (prepare && env_->CallStaticBooleanMethod(helper, prepare, reinterpret_cast<jlong>(api_), original_apk))
                        runtime_class_ = static_cast<jclass>(env_->NewGlobalRef(helper));
                } else if (error) {
                    const char* text = env_->GetStringUTFChars(error, nullptr);
                    if (text) { __android_log_print(ANDROID_LOG_ERROR, "DeviceLabRuntime", "prepare load: %s", text); env_->ReleaseStringUTFChars(error, text); }
                }
            }
            if (env_->ExceptionCheck()) { env_->ExceptionDescribe(); env_->ExceptionClear(); }
        }
        if (configured_ && broker_enabled) {
            const int socket = api_->connectCompanion();
            int broker_result = socket < 0 ? ECONNREFUSED : 0;
            if (socket >= 0) {
                timeval timeout{3, 0};
                setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                const int listener = install_uname_listener(proc_broker_enabled, platform_supervisor_);
                if (listener < 0) broker_result = errno;
                else {
                    const Request request{getpid(), getppid(), 1};
                    iovec data{const_cast<Request*>(&request), sizeof(request)};
                    char control[CMSG_SPACE(sizeof(int))]{};
                    msghdr message{};
                    message.msg_iov = &data;
                    message.msg_iovlen = 1;
                    message.msg_control = control;
                    message.msg_controllen = sizeof(control);
                    cmsghdr* header = CMSG_FIRSTHDR(&message);
                    header->cmsg_level = SOL_SOCKET;
                    header->cmsg_type = SCM_RIGHTS;
                    header->cmsg_len = CMSG_LEN(sizeof(int));
                    std::memcpy(CMSG_DATA(header), &listener, sizeof(listener));
                    if (sendmsg(socket, &message, MSG_NOSIGNAL) != sizeof(request)
                            || recv(socket, &broker_result, sizeof(broker_result), MSG_WAITALL) != sizeof(broker_result)) broker_result = EIO;
                    close(listener);
                }
                close(socket);
            }
            __android_log_print(broker_result == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                                "DeviceLabNamespace", "uname broker status=%d pid=%d", broker_result, getpid());
            __android_log_print(ANDROID_LOG_INFO, "DeviceLabNamespace", "notification domain=%s pid=%d",
                                platform_supervisor_ ? "platform" : "legacy", getpid());
            if (broker_result == 0 && proc_broker_enabled) setenv("DEVICE_LAB_PROC_BROKER", "1", 1);
            __android_log_print(ANDROID_LOG_INFO, "DeviceLabNamespace", "proc broker enabled=%d", broker_result == 0 && proc_broker_enabled);
            if (broker_result == 0 && proc_broker_enabled && policy_enabled) {
                const bool hooked = install_openat2_policy(api_);
                __android_log_print(hooked ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, "DeviceLabPolicy", "policy PLT installed=%d", hooked);
            }
        }
        if (configured_ && runtime_class_) api_->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (app_zygote_) {
            const int repaired = repair_detached_null_descriptors();
            __android_log_print(ANDROID_LOG_INFO, "DeviceLabNamespace", "app zygote null descriptors repaired=%d pid=%d", repaired, getpid());
            return;
        }
        const bool restored = restore_openat2_policy(api_);
        if (args->app_data_dir) {
            const char* directory = env_->GetStringUTFChars(args->app_data_dir, nullptr);
            if (directory) { save_openat2_policy(directory); env_->ReleaseStringUTFChars(args->app_data_dir, directory); }
        }
        if (restored) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        if (!configured_) return;
        const int result = refresh_property_mappings();
        __android_log_print(result == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                            "DeviceLabNamespace", "property remap status=%d pid=%d", result, getpid());
        if (result == 0 && runtime_class_) {
            jmethodID configure = env_->GetStaticMethodID(runtime_class_, "configure", "()V");
            if (configure) env_->CallStaticVoidMethod(runtime_class_, configure);
            if (env_->ExceptionCheck()) { env_->ExceptionDescribe(); env_->ExceptionClear(); }
        } else if (result == 0 && !runtime_library_.empty()) {
            jclass runtime = env_->FindClass("java/lang/Runtime");
            jmethodID load = runtime ? env_->GetStaticMethodID(runtime, "nativeLoad",
                    "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;") : nullptr;
            if (load) {
                jstring path = env_->NewStringUTF(runtime_library_.c_str());
                auto error = static_cast<jstring>(env_->CallStaticObjectMethod(runtime, load, path, nullptr, nullptr));
                if (error) {
                    const char* text = env_->GetStringUTFChars(error, nullptr);
                    if (text) { __android_log_print(ANDROID_LOG_ERROR, "DeviceLabRuntime", "native load: %s", text); env_->ReleaseStringUTFChars(error, text); }
                }
            }
            if (env_->ExceptionCheck()) { env_->ExceptionDescribe(); env_->ExceptionClear(); }
        }
    }
    void postServerSpecialize(const zygisk::ServerSpecializeArgs*) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
private:
    zygisk::Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    bool configured_ = false;
    bool app_zygote_ = false;
    bool platform_supervisor_ = false;
    std::string runtime_library_;
    std::string staged_apk_;
    jclass runtime_class_ = nullptr;
};
}

REGISTER_ZYGISK_MODULE(CpuNamespace)
REGISTER_ZYGISK_COMPANION(companion)
