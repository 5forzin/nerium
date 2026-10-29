#include "state.h"

static int initialized;

__attribute__((constructor)) static void boot_probe_start(void) {
    initialized = 0x30504c44;
    log_exec_state("constructor");
    char* entry = NULL;
    size_t entry_size = 0;
    unsigned entry_count = 0;
    for (char** value = environ; *value; ++value) {
        if (strncmp(*value, "LD_PRELOAD=", 11) == 0) {
            entry = *value;
            entry_size = strlen(entry);
            ++entry_count;
        }
    }
    int removed = unsetenv("LD_PRELOAD");
    int zeroed = removed == 0 && entry_count == 1;
    if (zeroed) {
        // Bionic removes pointers without freeing this initial exec-stack string.
        volatile unsigned char* bytes = (volatile unsigned char*)entry;
        for (size_t i = 0; i < entry_size; ++i) bytes[i] = 0;
    }
    int present = getenv("LD_PRELOAD") != NULL;
    __android_log_print(ANDROID_LOG_INFO, EXEC_PROBE_TAG,
        "{\"stage\":\"constructor_cleanup\",\"pid\":%d,\"preload_entry_count\":%u,"
        "\"unsetenv_result\":%d,\"zeroed_bytes\":%zu,\"libc_preload_present\":%s,\"passed\":%s}",
        getpid(), entry_count, removed, zeroed ? entry_size : 0,
        present ? "true" : "false", zeroed && !present ? "true" : "false");
}

__attribute__((visibility("default"))) int device_lab_boot_probe_marker(void) {
    return initialized;
}
