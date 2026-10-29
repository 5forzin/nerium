#include "state.h"
#include <errno.h>

int main(int argc, char** argv) {
    (void)argc;
    log_exec_state("wrapper");
#ifdef DEVICE_LAB_REAL_ZYGOTE
    const char* target = "/system/bin/app_process64";
#else
    const char* target = "/system/bin/device-lab-exec-helper";
#endif
    if (setenv("LD_PRELOAD", "/system/lib64/libdevice_lab_boot_probe.so", 1) != 0) return 120;
    argv[0] = (char*)target;
    execv(target, argv);
    __android_log_print(ANDROID_LOG_ERROR, EXEC_PROBE_TAG,
        "{\"stage\":\"exec_failed\",\"errno\":%d}", errno);
    return 121;
}
