#include <cerrno>
#include <cstdio>
#include <dlfcn.h>

int main() {
    void* library = dlopen("libselinux.so", RTLD_NOW);
    if (!library) { std::fprintf(stderr, "%s\n", dlerror()); return 2; }
    using Check = int (*)(const char*, const char*, const char*, const char*, void*);
    auto check = reinterpret_cast<Check>(dlsym(library, "selinux_check_access"));
    if (!check) return 2;
    struct Query { const char* source; const char* target; const char* type; const char* permission; };
    const Query queries[] = {
        {"u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem"},
        {"u:r:untrusted_app:s0", "u:r:magisk:s0", "binder", "call"},
        {"u:r:system_server:s0", "u:r:system_server:s0", "process", "getattr"},
    };
    for (const auto& query : queries) {
        errno = 0;
        int result = check(query.source, query.target, query.type, query.permission, nullptr);
        std::printf("%s %s %s %s result=%d errno=%d\n", query.source, query.target, query.type, query.permission, result, errno);
    }
    dlclose(library);
}
