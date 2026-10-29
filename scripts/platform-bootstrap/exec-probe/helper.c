#include "state.h"
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    log_exec_state("helper");
    int (*marker)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "device_lab_boot_probe_marker");
    int marker_value = marker ? marker() : 0;
    int mapped = 0;
    FILE* maps = fopen("/proc/self/maps", "re");
    if (maps) {
        char line[1024];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "/system/lib64/libdevice_lab_boot_probe.so")) mapped = 1;
        }
        fclose(maps);
    }
    int cleared = getenv("LD_PRELOAD") == NULL;
    int passed = marker_value == 0x30504c44 && mapped && cleared;
    __android_log_print(ANDROID_LOG_INFO, EXEC_PROBE_TAG,
        "{\"stage\":\"helper_result\",\"pid\":%d,\"marker\":%d,"
        "\"mapping_visible\":%s,\"preload_cleared\":%s,\"passed\":%s}",
        getpid(), marker_value, mapped ? "true" : "false", cleared ? "true" : "false",
        passed ? "true" : "false");
    return passed ? 0 : 1;
}
