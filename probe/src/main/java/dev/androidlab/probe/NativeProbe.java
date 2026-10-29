package dev.androidlab.probe;

import java.io.IOException;

final class NativeProbe {
    static {
        System.loadLibrary("deviceprobe");
    }

    static native String property(String name, boolean callback) throws IOException;
    static native String readFile(String path, int method) throws IOException;
    static native String runtimeArchitecture();
    static native boolean fileSemantics();
    static native String uname(boolean direct) throws IOException;
    static native String platform() throws IOException;
    static native String[] cpuFilesystem() throws IOException;
    static native String[] fileMetadata(String path) throws IOException;
    static native String[] graphics() throws IOException;
}
