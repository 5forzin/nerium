package dev.androidlab.module;

final class RuntimeProfile {
    private RuntimeProfile() {}
    static native boolean prepare(long api, String apkPath);
    static native void configure();
}
