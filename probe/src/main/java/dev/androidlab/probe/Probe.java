package dev.androidlab.probe;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.BatteryManager;
import android.os.Build;
import android.system.Os;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

final class Probe {
    private final JSONArray checks = new JSONArray();

    JSONObject collect(Context context) throws Exception {
        JSONObject report = new JSONObject();
        report.put("schema_version", 1);
        report.put("captured_at", Instant.now().toString());
        report.put("app_version", BuildConfig.VERSION_NAME);
        JSONObject device = new JSONObject();
        device.put("manufacturer", Build.MANUFACTURER);
        device.put("brand", Build.BRAND);
        device.put("model", Build.MODEL);
        device.put("device", Build.DEVICE);
        device.put("product", Build.PRODUCT);
        device.put("hardware", Build.HARDWARE);
        device.put("board", Build.BOARD);
        device.put("fingerprint", Build.FINGERPRINT);
        device.put("supported_abis", new JSONArray(Arrays.asList(Build.SUPPORTED_ABIS)));
        device.put("sdk", Build.VERSION.SDK_INT);
        device.put("android_release", Build.VERSION.RELEASE);
        report.put("device", device);

        String identity = (Build.MODEL + " " + Build.PRODUCT + " " + Build.HARDWARE
                + " " + Build.DEVICE + " " + Build.MANUFACTURER).toLowerCase(Locale.ROOT);
        add("java.identity", "java", contains(identity, "sdk", "emulator", "goldfish", "ranchu", "genymotion"), identity);
        add("java.fingerprint", "java", contains(Build.FINGERPRINT.toLowerCase(Locale.ROOT), "generic", "emulator", "sdk_gphone"), Build.FINGERPRINT);
        add("java.abi", "java", contains(Arrays.toString(Build.SUPPORTED_ABIS), "x86"), Arrays.toString(Build.SUPPORTED_ABIS));

        property("ro.kernel.qemu");
        property("ro.boot.qemu");
        property("ro.hardware");
        subprocess("ro.kernel.qemu");
        subprocess("ro.boot.qemu");
        subprocess("ro.hardware");
        nativeChecks(context, report);
        extendedChecks(report);

        for (String path : new String[]{"/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud"}) {
            try {
                add("file." + path, "filesystem", new File(path).exists(), path);
            } catch (SecurityException error) {
                unavailable("file." + path, "filesystem", error);
            }
        }

        JSONObject inventory = new JSONObject();
        JSONArray sensors = new JSONArray();
        SensorManager manager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (manager != null) {
            for (Sensor sensor : manager.getSensorList(Sensor.TYPE_ALL)) {
                JSONObject item = new JSONObject();
                item.put("name", sensor.getName());
                item.put("vendor", sensor.getVendor());
                item.put("type", sensor.getType());
                sensors.put(item);
            }
        }
        inventory.put("sensors", sensors);
        String sensorNames = sensors.toString().toLowerCase(Locale.ROOT);
        if (manager == null) {
            unavailable("sensor.metadata", "framework", new IllegalStateException("Sensor service unavailable"));
        } else {
            add("sensor.metadata", "framework", contains(sensorNames, "goldfish", "ranchu", "aosp", "emulator"), sensors.toString());
        }
        Intent battery = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            JSONObject state = new JSONObject();
            state.put("level", battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1));
            state.put("scale", battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1));
            state.put("temperature", battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1));
            state.put("status", battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1));
            inventory.put("battery", state);
        }
        report.put("inventory", inventory);
        report.put("checks", checks);
        JSONObject summary = new JSONObject();
        int detected = 0;
        int unavailable = 0;
        for (int i = 0; i < checks.length(); i++) {
            String status = checks.getJSONObject(i).getString("status");
            if (status.equals("detected")) detected++;
            if (status.equals("unavailable")) unavailable++;
        }
        summary.put("detected", detected);
        summary.put("unavailable", unavailable);
        summary.put("total", checks.length());
        report.put("summary", summary);
        report.put("integrity", "not_tested");
        report.put("interpretation", "Heuristic signals only. A clear check is not proof of a physical device. File visibility and permissions can limit observations.");
        return report;
    }

    private void nativeChecks(Context context, JSONObject report) throws Exception {
        String[] methods = {"fopen", "open", "openat", "syscall", "inline_syscall"};
        String[] names = {"ro.hardware", "ro.product.cpu.abilist", "ro.dalvik.vm.native.bridge", "ro.dalvik.vm.isa.arm64"};
        try {
            for (String name : names) {
                for (boolean callback : new boolean[]{false, true}) {
                    String id = "property.native." + (callback ? "callback." : "get.") + name;
                    try {
                        String value = NativeProbe.property(name, callback);
                        boolean detected = name.endsWith("abilist") ? value.contains("x86")
                                : name.endsWith("native.bridge") ? !value.isEmpty() && !value.equals("0")
                                : name.endsWith("isa.arm64") ? value.equals("x86_64") : propertySignal(name, value);
                        add(id, "native", detected, value);
                    } catch (java.io.IOException error) {
                        unavailable(id, "native", error);
                    }
                }
            }
            JSONObject cpu = new JSONObject();
            for (int method = 0; method < methods.length; method++) {
                String id = "native.cpuinfo." + methods[method];
                try {
                    String value = NativeProbe.readFile("/proc/cpuinfo", method);
                    if (value.isEmpty()) {
                        unavailable(id, "native", new java.io.IOException("Empty cpuinfo"));
                    } else {
                        cpu.put(methods[method], value);
                        add(id, method >= 3 ? "syscall_control" : "native", value.contains("hypervisor"), value);
                    }
                } catch (java.io.IOException error) {
                    unavailable(id, "native", error);
                }
            }
            report.put("native_cpuinfo", cpu);
            String architecture = NativeProbe.runtimeArchitecture();
            add("native.runtime_architecture", "instruction_set_control", architecture.contains("x86"), architecture);
            add("native.file_semantics", "io_control", !NativeProbe.fileSemantics(), "Read-only, close-on-exec, seek and repeated read");

            File control = new File(context.getFilesDir(), "native-control.txt");
            String expected = "Device Lab native I/O control\n";
            Files.write(control.toPath(), expected.getBytes(StandardCharsets.UTF_8));
            try {
                String[] metadata = NativeProbe.fileMetadata(control.getAbsolutePath());
                boolean valid = !metadata[0].equals("0x9fa0")
                        && new File(metadata[1]).getCanonicalPath().equals(control.getCanonicalPath());
                add("native.regular_file.metadata", "io_control", !valid, Arrays.toString(metadata));
            } catch (java.io.IOException error) {
                unavailable("native.regular_file.metadata", "io_control", error);
            }
            for (int method = 0; method < methods.length; method++) {
                String id = "native.regular_file." + methods[method];
                try {
                    String actual = NativeProbe.readFile(control.getAbsolutePath(), method);
                    add(id, "io_control", !expected.equals(actual), actual);
                } catch (java.io.IOException error) {
                    unavailable(id, "io_control", error);
                }
            }
        } catch (LinkageError error) {
            unavailable("native.library", "native", new IllegalStateException("Native library unavailable", error));
        }
    }

    @SuppressWarnings("deprecation")
    private void extendedChecks(JSONObject report) throws Exception {
        String primary = Build.SUPPORTED_ABIS.length == 0 ? "" : Build.SUPPORTED_ABIS[0];
        add("java.abi.primary_consistency", "identity_consistency", !primary.equals(Build.CPU_ABI),
                "CPU_ABI=" + Build.CPU_ABI + "; SUPPORTED_ABIS=" + Arrays.toString(Build.SUPPORTED_ABIS));
        String expected = Build.BRAND + "/" + Build.PRODUCT + "/" + Build.DEVICE + ":"
                + Build.VERSION.RELEASE + "/" + Build.ID + "/" + Build.VERSION.INCREMENTAL
                + ":" + Build.TYPE + "/" + Build.TAGS;
        add("java.build.fingerprint_fields", "identity_consistency", !Build.FINGERPRINT.equals(expected),
                "fingerprint=" + Build.FINGERPRINT + "; fields=" + expected);
        observe("kernel.java.uname", "kernel", () -> Os.uname().machine, value -> value.contains("x86"));
        observe("kernel.subprocess.uname", "kernel", () -> commandMachine(false), value -> value.contains("x86"));
        observe("kernel.subprocess.clean_env_uname", "kernel", () -> commandMachine(true), value -> value.contains("x86"));
        observe("kernel.native.uname", "kernel", () -> NativeProbe.uname(false), value -> value.contains("x86"));
        observe("kernel.inline.uname", "kernel", () -> NativeProbe.uname(true), value -> value.contains("x86"));
        observe("native.auxv.platform", "kernel", NativeProbe::platform, value -> value.contains("x86"));
        try {
            String[] metadata = NativeProbe.cpuFilesystem();
            add("native.cpuinfo.filesystem_type", "filesystem_metadata", !metadata[0].equals("0x9fa0"), metadata[0]);
            add("native.cpuinfo.descriptor_alias", "filesystem_metadata", !metadata[1].equals("/proc/cpuinfo"), metadata[1]);
        } catch (java.io.IOException error) {
            unavailable("native.cpuinfo.filesystem_type", "filesystem_metadata", error);
            unavailable("native.cpuinfo.descriptor_alias", "filesystem_metadata", error);
        }
        observe("native.maps.translation", "translation", () -> matchingLines("/proc/self/maps",
                "libndk_translation", "libhoudini"), value -> !value.equals("none"));
        observe("native.maps.instrumentation", "instrumentation", () -> matchingLines("/proc/self/maps",
                "zygisk", "lsposed", "liblspd", "/data/adb/", "libdevicelab.so", "dev.androidlab.module"),
                value -> !value.equals("none"));
        observe("native.mountinfo.profile", "filesystem_metadata", () -> matchingLines("/proc/self/mountinfo",
                " /proc/cpuinfo ", "device_lab_cpu", "device-lab-cpuinfo"), value -> !value.equals("none"));
        observe("native.cpuinfo.alias", "syscall_control", () -> NativeProbe.readFile("/proc/self/../cpuinfo", 4),
                value -> value.contains("hypervisor"));
        JSONObject graphics = new JSONObject();
        String[] graphicsNames = {"vendor", "renderer", "version", "egl_vendor"};
        try {
            String[] values = NativeProbe.graphics();
            for (int i = 0; i < graphicsNames.length; i++) {
                graphics.put(graphicsNames[i], values[i]);
                if (values[i].isEmpty()) unavailable("graphics." + graphicsNames[i], "graphics", new java.io.IOException("Empty graphics string"));
                else add("graphics." + graphicsNames[i], "graphics", contains(values[i].toLowerCase(Locale.ROOT),
                        "emulator", "gfxstream", "goldfish", "swiftshader", "emugl", "translator"), values[i]);
            }
            boolean armIdentity = values[0].equalsIgnoreCase("ARM") || values[1].toLowerCase(Locale.ROOT).contains("mali");
            boolean desktopDriver = contains(values[2].toLowerCase(Locale.ROOT), "nvidia", "intel", "radeon");
            add("graphics.identity_consistency", "identity_consistency", armIdentity && desktopDriver,
                    "vendor=" + values[0] + "; renderer=" + values[1] + "; version=" + values[2]);
        } catch (java.io.IOException error) {
            for (String name : graphicsNames) unavailable("graphics." + name, "graphics", error);
            unavailable("graphics.identity_consistency", "identity_consistency", error);
        }
        report.put("graphics", graphics);
        String[] propertyNames = {"ro.build.id", "ro.build.type", "ro.build.tags", "ro.build.version.incremental"};
        String[] expectedProperties = {Build.ID, Build.TYPE, Build.TAGS, Build.VERSION.INCREMENTAL};
        JSONObject propertyValues = new JSONObject();
        boolean mismatch = false;
        try {
            for (int i = 0; i < propertyNames.length; i++) {
                String getter = NativeProbe.property(propertyNames[i], false);
                String callback = NativeProbe.property(propertyNames[i], true);
                propertyValues.put(propertyNames[i], new JSONObject().put("get", getter).put("callback", callback).put("java", expectedProperties[i]));
                mismatch |= !getter.equals(expectedProperties[i]) || !callback.equals(expectedProperties[i]);
            }
            add("native.identity.property_consistency", "identity_consistency", mismatch, propertyValues.toString());
        } catch (java.io.IOException error) {
            unavailable("native.identity.property_consistency", "identity_consistency", error);
        }
    }

    private interface Observation { String read() throws Exception; }

    private void observe(String id, String layer, Observation source, Predicate<String> detected) throws Exception {
        String value;
        try { value = source.read(); }
        catch (Exception error) { unavailable(id, layer, error); return; }
        if (value == null || value.isEmpty()) unavailable(id, layer, new java.io.IOException("Empty observation"));
        else add(id, layer, detected.test(value), value);
    }

    private String matchingLines(String path, String... tokens) throws java.io.IOException {
        String text = NativeProbe.readFile(path, 4);
        if (text.isEmpty()) throw new java.io.IOException("Empty " + path);
        String matches = Arrays.stream(text.split("\n")).filter(line -> contains(line.toLowerCase(Locale.ROOT), tokens))
                .limit(20).collect(java.util.stream.Collectors.joining("\n"));
        return matches.isEmpty() ? "none" : matches;
    }

    private String commandMachine(boolean cleanEnvironment) throws Exception {
        ProcessBuilder builder = new ProcessBuilder("/system/bin/uname", "-m").redirectErrorStream(true);
        if (cleanEnvironment) builder.environment().clear();
        Process process = builder.start();
        try {
            if (!process.waitFor(3, TimeUnit.SECONDS)) throw new java.io.IOException("uname timed out");
            String result;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                result = reader.lines().collect(java.util.stream.Collectors.joining("\n")).trim();
            }
            if (process.exitValue() != 0) throw new java.io.IOException("uname failed: " + result);
            return result;
        } finally { if (process.isAlive()) process.destroyForcibly(); }
    }

    private void property(String name) throws Exception {
        String id = "property.java." + name;
        try {
            Class<?> type = Class.forName("android.os.SystemProperties");
            Method method = type.getDeclaredMethod("get", String.class, String.class);
            String value = (String) method.invoke(null, name, "");
            add(id, "java", propertySignal(name, value), value);
        } catch (ReflectiveOperationException | SecurityException error) {
            unavailable(id, "java", error);
        }
    }

    private void subprocess(String name) throws Exception {
        String id = "property.subprocess." + name;
        Process process = null;
        try {
            process = new ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start();
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                unavailable(id, "subprocess", new IllegalStateException("getprop timed out"));
                return;
            }
            String value;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                value = reader.lines().collect(java.util.stream.Collectors.joining("\n")).trim();
            }
            if (process.exitValue() != 0) {
                unavailable(id, "subprocess", new IllegalStateException("getprop failed: " + value));
                return;
            }
            add(id, "subprocess", propertySignal(name, value), value);
        } catch (java.io.IOException error) {
            unavailable(id, "subprocess", error);
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
    }

    private boolean propertySignal(String name, String value) {
        return name.endsWith("qemu") ? value.equals("1")
                : contains(value.toLowerCase(Locale.ROOT), "goldfish", "ranchu", "vbox");
    }

    private static boolean contains(String value, String... needles) {
        for (String needle : needles) if (value.contains(needle)) return true;
        return false;
    }

    private void add(String id, String layer, boolean detected, String observed) throws Exception {
        checks.put(new JSONObject().put("id", id).put("layer", layer)
                .put("status", detected ? "detected" : "clear").put("observed", observed));
    }

    private void unavailable(String id, String layer, Exception error) throws Exception {
        checks.put(new JSONObject().put("id", id).put("layer", layer)
                .put("status", "unavailable").put("observed", error.getClass().getSimpleName() + ": " + error.getMessage()));
    }
}
