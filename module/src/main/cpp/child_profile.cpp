#include "profile.hpp"

#include <dlfcn.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>

using Callback = void (*)(void*, const char*, const char*, uint32_t);
using ReadCallback = void (*)(const prop_info*, Callback, void*);
using Getter = int (*)(const char*, char*);

extern "C" __attribute__((visibility("default")))
int uname(struct utsname* value) {
    using Uname = int (*)(struct utsname*);
    static const auto original = reinterpret_cast<Uname>(dlsym(RTLD_NEXT, "uname"));
    const int result = original(value);
    if (result == 0) std::strcpy(value->machine, "aarch64");
    return result;
}

extern "C" __attribute__((visibility("default")))
int __system_property_get(const char* name, char* value) {
    if (const char* replacement = device_lab::replacement_property(name)) {
        const size_t length = std::strlen(replacement);
        std::memcpy(value, replacement, length + 1);
        return static_cast<int>(length);
    }
    static const auto original = reinterpret_cast<Getter>(dlsym(RTLD_NEXT, "__system_property_get"));
    return original(name, value);
}

extern "C" __attribute__((visibility("default")))
void __system_property_read_callback(const prop_info* info, Callback callback, void* cookie) {
    struct Context { Callback callback; void* cookie; } context{callback, cookie};
    static const auto original = reinterpret_cast<ReadCallback>(dlsym(RTLD_NEXT, "__system_property_read_callback"));
    original(info, [](void* data, const char* name, const char* value, uint32_t serial) {
        const auto& state = *static_cast<Context*>(data);
        const char* replacement = device_lab::replacement_property(name);
        state.callback(state.cookie, name, replacement == nullptr ? value : replacement, serial);
    }, &context);
}
