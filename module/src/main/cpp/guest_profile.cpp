#include <jni.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/auxv.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace {
std::array<Elf64_auxv_t, 130> guest_auxv{};
constexpr char platform[] = "aarch64";
bool configured = false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_androidlab_module_GuestProfile_configurePlatform(JNIEnv* env, jclass) {
    if (configured) return env->NewStringUTF("already_configured");
    using SharedGlobals = void* (*)();
    auto shared = reinterpret_cast<SharedGlobals>(dlsym(RTLD_DEFAULT, "__loader_shared_globals"));
    const auto* getter = reinterpret_cast<const uint32_t*>(dlsym(RTLD_DEFAULT, "getauxval"));
    if (getter == nullptr) return env->NewStringUTF("getter_symbol_unavailable");
    // This private layout is restricted to the pinned Android 14 ARM64 libc.
    // Its getter loads the auxv pointer with: ldr x8, [x0, #0x418].
    const bool layout_matches = getter[0] == 0xa9be7bfd && getter[3] == 0xaa0003f3 && getter[5] == 0xf9420c08
            && (getter[4] & 0xfc000000) == 0x94000000;
    if (!layout_matches) return env->NewStringUTF("unsupported_libc_layout");
    if (shared == nullptr) {
        // The loader does not export its private symbol to this namespace.
        // Resolve the getter's existing call to __libc_shared_globals instead.
        if ((getter[4] & 0xfc000000) != 0x94000000)
            return env->NewStringUTF("unsupported_getter_call");
        const int32_t displacement = static_cast<int32_t>(getter[4] << 6) >> 4;
        shared = reinterpret_cast<SharedGlobals>(reinterpret_cast<uintptr_t>(getter + 4) + displacement);
    }
    auto* globals = static_cast<unsigned char*>(shared());
    if (globals == nullptr) return env->NewStringUTF("shared_globals_unavailable");
    auto** slot = reinterpret_cast<Elf64_auxv_t**>(globals + 0x418);
    Elf64_auxv_t* original = *slot;
    if (original == nullptr) return env->NewStringUTF("auxv_unavailable");
    size_t size = 0;
    bool page_size_matches = false;
    for (; size < guest_auxv.size() - 2 && original[size].a_type != AT_NULL; ++size) {
        guest_auxv[size] = original[size];
        if (original[size].a_type == AT_PAGESZ)
            page_size_matches = original[size].a_un.a_val == static_cast<unsigned long>(sysconf(_SC_PAGESIZE));
    }
    if (size == guest_auxv.size() - 2 || !page_size_matches)
        return env->NewStringUTF("auxv_validation_failed");
    bool replaced = false;
    for (size_t i = 0; i < size; ++i) {
        if (guest_auxv[i].a_type == AT_PLATFORM) {
            guest_auxv[i].a_un.a_val = reinterpret_cast<uintptr_t>(platform);
            replaced = true;
        }
    }
    if (!replaced) {
        guest_auxv[size].a_type = AT_PLATFORM;
        guest_auxv[size++].a_un.a_val = reinterpret_cast<uintptr_t>(platform);
    }
    guest_auxv[size] = {};
    // Publish an immutable copy; readers of the old table retain valid storage.
    __atomic_store_n(slot, guest_auxv.data(), __ATOMIC_RELEASE);
    configured = true;
    return env->NewStringUTF("configured");
}
