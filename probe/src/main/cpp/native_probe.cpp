#include <fcntl.h>
#include <jni.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
long inline_syscall(long number, long first, long second, long third, long fourth = 0) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = fourth;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third), "r"(r10)
                     : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    long result = x0;
#else
#error Unsupported inline syscall architecture
#endif
    if (result < 0 && result >= -4095) {
        errno = static_cast<int>(-result);
        return -1;
    }
    return result;
}

void io_error(JNIEnv* env, const char* operation) {
    std::string message = std::string(operation) + ": " + std::strerror(errno);
    env->ThrowNew(env->FindClass("java/io/IOException"), message.c_str());
}

jobjectArray strings(JNIEnv* env, const std::vector<std::string>& values) {
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(values.size()), env->FindClass("java/lang/String"), nullptr);
    if (result == nullptr) return nullptr;
    for (size_t i = 0; i < values.size(); ++i) {
        jstring value = env->NewStringUTF(values[i].c_str());
        if (value == nullptr) return nullptr;
        env->SetObjectArrayElement(result, static_cast<jsize>(i), value);
        env->DeleteLocalRef(value);
    }
    return result;
}

std::string read_stream(FILE* stream, bool& success) {
    std::string text;
    char buffer[4096];
    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), stream)) > 0) text.append(buffer, count);
    success = !ferror(stream);
    return text;
}

std::string read_fd(int fd, int method, bool& success) {
    std::string text;
    char buffer[4096];
    ssize_t count;
    while ((count = method == 4 ? inline_syscall(SYS_read, fd, reinterpret_cast<long>(buffer), sizeof(buffer))
                    : method == 3 ? syscall(SYS_read, fd, buffer, sizeof(buffer)) : read(fd, buffer, sizeof(buffer))) > 0) {
        text.append(buffer, count);
    }
    success = count == 0;
    return text;
}
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_androidlab_probe_NativeProbe_property(JNIEnv* env, jclass, jstring input, jboolean callback) {
    const char* name = env->GetStringUTFChars(input, nullptr);
    if (name == nullptr) return nullptr;
    std::string result;
    if (callback) {
        const prop_info* info = __system_property_find(name);
        if (info != nullptr) {
            __system_property_read_callback(info, [](void* cookie, const char*, const char* value, uint32_t) {
                *static_cast<std::string*>(cookie) = value;
            }, &result);
        }
    } else {
        char value[PROP_VALUE_MAX]{};
        const int length = __system_property_get(name, value);
        if (length < 0 || static_cast<size_t>(length) >= sizeof(value) || std::strlen(value) != static_cast<size_t>(length)) {
            env->ReleaseStringUTFChars(input, name);
            env->ThrowNew(env->FindClass("java/io/IOException"), "Invalid property length or termination");
            return nullptr;
        }
        result = value;
    }
    env->ReleaseStringUTFChars(input, name);
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_androidlab_probe_NativeProbe_readFile(JNIEnv* env, jclass, jstring input, jint method) {
    const char* path = env->GetStringUTFChars(input, nullptr);
    if (path == nullptr) return nullptr;
    std::string text;
    bool success = false;
    if (method == 0) {
        FILE* stream = fopen(path, "re");
        env->ReleaseStringUTFChars(input, path);
        if (stream == nullptr) {
            io_error(env, "fopen");
            return nullptr;
        }
        text = read_stream(stream, success);
        const int saved = errno;
        fclose(stream);
        errno = saved;
    } else {
        int fd = -1;
        if (method == 1) fd = open(path, O_RDONLY | O_CLOEXEC);
        if (method == 2) fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
        if (method == 3) fd = static_cast<int>(syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
        if (method == 4) fd = static_cast<int>(inline_syscall(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC));
        env->ReleaseStringUTFChars(input, path);
        if (fd < 0) {
            io_error(env, "open");
            return nullptr;
        }
        text = read_fd(fd, method, success);
        const int saved = errno;
        close(fd);
        errno = saved;
    }
    if (!success) {
        io_error(env, "read");
        return nullptr;
    }
    return env->NewStringUTF(text.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_androidlab_probe_NativeProbe_runtimeArchitecture(JNIEnv* env, jclass) {
#if defined(__x86_64__)
    return env->NewStringUTF("x86_64");
#elif defined(__aarch64__)
    return env->NewStringUTF("arm64");
#else
    return env->NewStringUTF("other");
#endif
}

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_androidlab_probe_NativeProbe_fileSemantics(JNIEnv*, jclass) {
    const int fd = open("/proc/cpuinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char first[64]{};
    char second[64]{};
    const ssize_t count = read(fd, first, sizeof(first));
    const bool rewind = lseek(fd, 0, SEEK_SET) == 0;
    const ssize_t repeated = read(fd, second, sizeof(second));
    const bool readonly = (fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY;
    const bool close_on_exec = (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
    close(fd);
    return count > 0 && rewind && repeated == count && std::memcmp(first, second, count) == 0 && readonly && close_on_exec;
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_androidlab_probe_NativeProbe_uname(JNIEnv* env, jclass, jboolean direct) {
    struct utsname value{};
    const long result = direct ? inline_syscall(SYS_uname, reinterpret_cast<long>(&value), 0, 0) : uname(&value);
    if (result != 0) { io_error(env, "uname"); return nullptr; }
    return env->NewStringUTF(value.machine);
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_androidlab_probe_NativeProbe_platform(JNIEnv* env, jclass) {
    const auto* value = reinterpret_cast<const char*>(getauxval(AT_PLATFORM));
    if (value == nullptr) {
        env->ThrowNew(env->FindClass("java/io/IOException"), "AT_PLATFORM unavailable");
        return nullptr;
    }
    return env->NewStringUTF(value);
}

static jobjectArray file_metadata(JNIEnv* env, const char* input) {
    const int fd = static_cast<int>(inline_syscall(SYS_openat, AT_FDCWD,
        reinterpret_cast<long>(input), O_RDONLY | O_CLOEXEC));
    if (fd < 0) { io_error(env, "CPU metadata open"); return nullptr; }
    struct statfs filesystem{};
    char path[64], target[4096];
    std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    const long stat_result = inline_syscall(SYS_fstatfs, fd, reinterpret_cast<long>(&filesystem), 0);
    const int stat_error = errno;
    const long length = inline_syscall(SYS_readlinkat, AT_FDCWD, reinterpret_cast<long>(path),
                                       reinterpret_cast<long>(target), sizeof(target) - 1);
    const int link_error = errno;
    close(fd);
    if (stat_result != 0) { errno = stat_error; io_error(env, "CPU fstatfs"); return nullptr; }
    if (length < 0) { errno = link_error; io_error(env, "CPU readlinkat"); return nullptr; }
    target[length] = '\0';
    char magic[32];
    std::snprintf(magic, sizeof(magic), "0x%llx", static_cast<unsigned long long>(filesystem.f_type));
    return strings(env, {magic, target});
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_dev_androidlab_probe_NativeProbe_cpuFilesystem(JNIEnv* env, jclass) {
    return file_metadata(env, "/proc/cpuinfo");
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_dev_androidlab_probe_NativeProbe_fileMetadata(JNIEnv* env, jclass, jstring input) {
    const char* path = env->GetStringUTFChars(input, nullptr);
    if (path == nullptr) return nullptr;
    jobjectArray result = file_metadata(env, path);
    env->ReleaseStringUTFChars(input, path);
    return result;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_dev_androidlab_probe_NativeProbe_graphics(JNIEnv* env, jclass) {
    const EGLDisplay previous_display = eglGetCurrentDisplay();
    const EGLContext previous_context = eglGetCurrentContext();
    const EGLSurface previous_draw = eglGetCurrentSurface(EGL_DRAW);
    const EGLSurface previous_read = eglGetCurrentSurface(EGL_READ);
    const EGLenum previous_api = eglQueryAPI();
    const EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLConfig config{};
    EGLint count = 0;
    const EGLint attributes[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE};
    if (display == EGL_NO_DISPLAY || !eglInitialize(display, nullptr, nullptr)
            || !eglChooseConfig(display, attributes, &config, 1, &count) || count != 1) {
        env->ThrowNew(env->FindClass("java/io/IOException"), "EGL configuration unavailable");
        return nullptr;
    }
    eglBindAPI(EGL_OPENGL_ES_API);
    const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    const EGLint surface_attributes[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
    const EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    const EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attributes);
    const bool current = context != EGL_NO_CONTEXT && surface != EGL_NO_SURFACE
            && eglMakeCurrent(display, surface, surface, context);
    std::vector<std::string> values;
    if (current) {
        for (GLenum name : {GL_VENDOR, GL_RENDERER, GL_VERSION}) {
            const auto* value = glGetString(name);
            values.emplace_back(value == nullptr ? "" : reinterpret_cast<const char*>(value));
        }
        const char* vendor = eglQueryString(display, EGL_VENDOR);
        values.emplace_back(vendor == nullptr ? "" : vendor);
        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    }
    if (surface != EGL_NO_SURFACE) eglDestroySurface(display, surface);
    if (context != EGL_NO_CONTEXT) eglDestroyContext(display, context);
    eglBindAPI(previous_api);
    if (previous_context != EGL_NO_CONTEXT) eglMakeCurrent(previous_display, previous_draw, previous_read, previous_context);
    // The default display can also belong to Android's RenderThread; do not terminate it here.
    if (!current) {
        env->ThrowNew(env->FindClass("java/io/IOException"), "EGL context unavailable");
        return nullptr;
    }
    return strings(env, values);
}
