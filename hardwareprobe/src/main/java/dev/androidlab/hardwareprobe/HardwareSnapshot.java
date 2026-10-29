package dev.androidlab.hardwareprobe;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.graphics.Rect;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.hardware.display.DisplayManager;
import android.media.AudioManager;
import android.media.MediaCodecList;
import android.media.MediaDrm;
import android.media.MicrophoneInfo;
import android.os.BatteryManager;
import android.os.Build;
import android.os.PowerManager;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.InputDevice;
import android.view.WindowManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Collects the app-visible hardware view of whatever device it runs on. Every
 * section is independent: a failure is recorded, never swallowed, so a
 * snapshot from one device can be diffed against another without guessing
 * what ran.
 */
final class HardwareSnapshot {
    private static final UUID WIDEVINE_UUID = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);

    /** Optional progress observer used by the instrumentation runner. */
    interface Sink {
        void section(String name, String compactJson);
    }

    static volatile Sink sink;

    /** Wall-clock budget for a single section on remote hardware. */
    private static final long SECTION_TIMEOUT_MILLIS = 20_000;

    JSONObject collect(Context context) throws Exception {
        JSONObject report = new JSONObject();
        report.put("schema_version", 1);
        report.put("kind", "hardware-snapshot");
        report.put("collected_at", System.currentTimeMillis());
        section(report, "identity", () -> identity());
        section(report, "properties", () -> systemProperties());
        section(report, "kernel", () -> kernel());
        section(report, "cpu", () -> cpu());
        section(report, "sensors", () -> sensors(context));
        section(report, "graphics", () -> graphics());
        section(report, "display", () -> display(context));
        section(report, "cameras", () -> cameras(context));
        section(report, "codecs", () -> codecs());
        section(report, "drm", () -> drm());
        section(report, "features", () -> features(context));
        section(report, "input_devices", () -> inputDevices());
        section(report, "gnss", () -> gnss(context));
        section(report, "memory", () -> memory(context));
        section(report, "storage", () -> storage(context));
        section(report, "power", () -> power(context));
        section(report, "audio", () -> audio(context));
        section(report, "telephony", () -> telephony(context));
        return report;
    }

    private interface Section {
        Object run() throws Exception;
    }

    private static void section(JSONObject report, String name, Section body) {
        Object result;
        java.util.concurrent.FutureTask<Object> task = new java.util.concurrent.FutureTask<>(() -> body.run());
        Thread worker = new Thread(task, "section-" + name);
        worker.setDaemon(true);
        worker.start();
        try {
            result = task.get(SECTION_TIMEOUT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (Throwable timeoutOrFailure) {
            worker.interrupt();
            try {
                result = new JSONObject().put("error", String.valueOf(timeoutOrFailure));
            } catch (Exception nested) {
                result = null;
            }
        }
        try {
            report.put(name, result);
        } catch (Exception ignored) {
        }
        Sink observer = sink;
        if (observer != null) {
            try {
                observer.section(name, String.valueOf(result));
            } catch (Exception ignored) {
            }
        }
    }

    private interface Value {
        Object value() throws Exception;
    }

    /** Records one field independently; a single unsupported API level does not lose the section. */
    private static void put(JSONObject out, String key, Value value) {
        try {
            out.put(key, value.value());
        } catch (Throwable error) {
            try {
                out.put(key, new JSONObject().put("error", error.toString()));
            } catch (Exception ignored) {
            }
        }
    }

    private static JSONObject identity() throws Exception {
        JSONObject out = new JSONObject();
        out.put("manufacturer", Build.MANUFACTURER);
        out.put("brand", Build.BRAND);
        out.put("model", Build.MODEL);
        out.put("device", Build.DEVICE);
        out.put("product", Build.PRODUCT);
        out.put("board", Build.BOARD);
        out.put("hardware", Build.HARDWARE);
        out.put("bootloader", Build.BOOTLOADER);
        put(out, "radio", Build::getRadioVersion);
        out.put("fingerprint", Build.FINGERPRINT);
        out.put("build_id", Build.ID);
        out.put("build_type", Build.TYPE);
        out.put("build_tags", Build.TAGS);
        out.put("build_incremental", Build.VERSION.INCREMENTAL);
        out.put("security_patch", Build.VERSION.SECURITY_PATCH);
        out.put("release", Build.VERSION.RELEASE);
        out.put("sdk", Build.VERSION.SDK_INT);
        out.put("abis", stringArray(Build.SUPPORTED_ABIS));
        return out;
    }

    private static JSONObject systemProperties() throws Exception {
        String dump = new String(exec("getprop"), StandardCharsets.UTF_8);
        JSONObject values = new JSONObject();
        for (String line : dump.split("\n")) {
            java.util.regex.Matcher match =
                    java.util.regex.Pattern.compile("^\\[(.+)]?: \\[(.*)]$").matcher(line);
            if (match.matches()) {
                values.put(match.group(1), match.group(2));
            }
        }
        return new JSONObject().put("values", values).put("raw", dump);
    }

    private static JSONObject kernel() throws Exception {
        JSONObject out = new JSONObject();
        out.put("uname", new String(exec("uname", "-a"), StandardCharsets.UTF_8).trim());
        out.put("cpuinfo", readFile("/proc/cpuinfo"));
        putFile(out, "version", "/proc/version");
        putFile(out, "meminfo", "/proc/meminfo");
        return out;
    }

    private static JSONObject cpu() throws Exception {
        JSONObject out = new JSONObject();
        putFile(out, "online", "/sys/devices/system/cpu/online");
        putFile(out, "present", "/sys/devices/system/cpu/present");
        putFile(out, "possible", "/sys/devices/system/cpu/possible");
        File[] entries = new File("/sys/devices/system/cpu").listFiles();
        JSONArray cores = new JSONArray();
        if (entries != null) {
            for (File entry : entries) {
                if (!entry.getName().matches("cpu\\d+")) continue;
                JSONObject core = new JSONObject();
                core.put("name", entry.getName());
                File cpufreq = new File(entry, "cpufreq");
                if (cpufreq.isDirectory()) {
                    putFile(core, "cpuinfo_min_freq", new File(cpufreq, "cpuinfo_min_freq").getPath());
                    putFile(core, "cpuinfo_max_freq", new File(cpufreq, "cpuinfo_max_freq").getPath());
                    putFile(core, "scaling_driver", new File(cpufreq, "scaling_driver").getPath());
                    putFile(core, "scaling_governor", new File(cpufreq, "scaling_governor").getPath());
                    putFile(core, "related_cpus", new File(cpufreq, "related_cpus").getPath());
                    putFile(core, "time_in_state", new File(cpufreq, "time_in_state").getPath());
                }
                cores.put(core);
            }
        }
        out.put("cores", cores);
        return out;
    }

    private static JSONObject sensors(Context context) throws Exception {
        SensorManager manager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no sensor service");
        List<Sensor> available = manager.getSensorList(Sensor.TYPE_ALL);
        JSONArray list = new JSONArray();
        for (Sensor sensor : available) {
            JSONObject item = new JSONObject();
            item.put("name", sensor.getName());
            item.put("vendor", sensor.getVendor());
            item.put("version", sensor.getVersion());
            item.put("type", sensor.getType());
            item.put("string_type", sensor.getStringType());
            item.put("maximum_range", (double) sensor.getMaximumRange());
            item.put("resolution", (double) sensor.getResolution());
            item.put("power_milli_amps", (double) sensor.getPower());
            item.put("min_delay_micros", sensor.getMinDelay());
            item.put("max_delay_micros", sensor.getMaxDelay());
            item.put("fifo_max_event_count", sensor.getFifoMaxEventCount());
            item.put("reporting_mode", sensor.getReportingMode());
            item.put("is_wake_up", sensor.isWakeUpSensor());
            item.put("is_additional_info_supported", sensor.isAdditionalInfoSupported());
            list.put(item);
        }
        return new JSONObject().put("count", available.size()).put("list", list);
    }

    private static JSONObject graphics() throws Exception {
        // A one-pixel pbuffer GL context is enough to read the driver strings
        // without any surface or permission.
        android.opengl.EGLDisplay display =
                android.opengl.EGL14.eglGetDisplay(android.opengl.EGL14.EGL_DEFAULT_DISPLAY);
        if (display == android.opengl.EGL14.EGL_NO_DISPLAY) {
            return new JSONObject().put("error", "no default EGL display");
        }
        int[] major = new int[1];
        int[] minor = new int[1];
        if (!android.opengl.EGL14.eglInitialize(display, major, 0, minor, 0)) {
            return new JSONObject().put("error", "eglInitialize failed");
        }
        try {
            JSONObject out = new JSONObject();
            out.put("egl_version", android.opengl.EGL14.eglQueryString(display, android.opengl.EGL14.EGL_VERSION));
            out.put("egl_vendor", android.opengl.EGL14.eglQueryString(display, android.opengl.EGL14.EGL_VENDOR));
            out.put("egl_client_extensions",
                    android.opengl.EGL14.eglQueryString(display, android.opengl.EGL14.EGL_EXTENSIONS));
            int[] configAttribs = {
                    android.opengl.EGL14.EGL_RENDERABLE_TYPE, android.opengl.EGLExt.EGL_OPENGL_ES3_BIT_KHR,
                    android.opengl.EGL14.EGL_SURFACE_TYPE, android.opengl.EGL14.EGL_PBUFFER_BIT,
                    android.opengl.EGL14.EGL_RED_SIZE, 8,
                    android.opengl.EGL14.EGL_GREEN_SIZE, 8,
                    android.opengl.EGL14.EGL_BLUE_SIZE, 8,
                    android.opengl.EGL14.EGL_ALPHA_SIZE, 8,
                    android.opengl.EGL14.EGL_NONE};
            android.opengl.EGLConfig[] configs = new android.opengl.EGLConfig[1];
            int[] matched = new int[1];
            if (!android.opengl.EGL14.eglChooseConfig(display, configAttribs, 0, configs, 0, 1, matched, 0)
                    || matched[0] < 1) {
                out.put("error", "no ES3 pbuffer config");
                return out;
            }
            int[] surfaceAttribs = {
                    android.opengl.EGL14.EGL_WIDTH, 1, android.opengl.EGL14.EGL_HEIGHT, 1, android.opengl.EGL14.EGL_NONE};
            android.opengl.EGLSurface surface =
                    android.opengl.EGL14.eglCreatePbufferSurface(display, configs[0], surfaceAttribs, 0);
            int[] contextAttribs = {
                    android.opengl.EGL14.EGL_CONTEXT_CLIENT_VERSION, 3, android.opengl.EGL14.EGL_NONE};
            android.opengl.EGLContext context = android.opengl.EGL14.eglCreateContext(
                    display, configs[0], android.opengl.EGL14.EGL_NO_CONTEXT, contextAttribs, 0);
            try {
                if (!android.opengl.EGL14.eglMakeCurrent(display, surface, surface, context)) {
                    out.put("error", "eglMakeCurrent failed");
                    return out;
                }
                out.put("gles_vendor", android.opengl.GLES30.glGetString(android.opengl.GLES30.GL_VENDOR));
                out.put("gles_renderer", android.opengl.GLES30.glGetString(android.opengl.GLES30.GL_RENDERER));
                out.put("gles_version", android.opengl.GLES30.glGetString(android.opengl.GLES30.GL_VERSION));
                out.put("gles_shading_language",
                        android.opengl.GLES30.glGetString(android.opengl.GLES30.GL_SHADING_LANGUAGE_VERSION));
                out.put("gles_extensions", android.opengl.GLES30.glGetString(android.opengl.GLES30.GL_EXTENSIONS));
                return out;
            } finally {
                android.opengl.EGL14.eglMakeCurrent(display, android.opengl.EGL14.EGL_NO_SURFACE,
                        android.opengl.EGL14.EGL_NO_SURFACE, android.opengl.EGL14.EGL_NO_CONTEXT);
                if (surface != null) {
                    android.opengl.EGL14.eglDestroySurface(display, surface);
                }
                if (context != null) {
                    android.opengl.EGL14.eglDestroyContext(display, context);
                }
            }
        } finally {
            android.opengl.EGL14.eglTerminate(display);
        }
    }

    private static JSONObject display(Context context) throws Exception {
        JSONObject out = new JSONObject();
        DisplayManager manager = (DisplayManager) context.getSystemService(Context.DISPLAY_SERVICE);
        if (manager == null) return out.put("error", "no display service");
        JSONArray list = new JSONArray();
        for (Display display : manager.getDisplays()) {
            JSONObject item = new JSONObject();
            item.put("name", display.getName());
            item.put("display_id", display.getDisplayId());
            item.put("mode", display.getMode().getPhysicalWidth() + "x"
                    + display.getMode().getPhysicalHeight() + "@" + display.getMode().getRefreshRate());
            JSONArray modes = new JSONArray();
            for (Display.Mode mode : display.getSupportedModes()) {
                JSONObject entry = new JSONObject();
                entry.put("width", mode.getPhysicalWidth());
                entry.put("height", mode.getPhysicalHeight());
                entry.put("refresh_rate", (double) mode.getRefreshRate());
                entry.put("mode_id", mode.getModeId());
                modes.put(entry);
            }
            item.put("modes", modes);
            if (display.getHdrCapabilities() != null) {
                item.put("hdr_types", intArray(display.getHdrCapabilities().getSupportedHdrTypes()));
            }
            item.put("is_wide_color_gamut", display.isWideColorGamut());
            if (Build.VERSION.SDK_INT >= 29) {
                put(item, "preferred_wide_gamut_color_space",
                        () -> String.valueOf(display.getPreferredWideGamutColorSpace()));
            }
            DisplayMetrics metrics = new DisplayMetrics();
            display.getRealMetrics(metrics);
            item.put("real_density_dpi", metrics.densityDpi);
            list.put(item);
        }
        out.put("displays", list);
        if (Build.VERSION.SDK_INT >= 30) {
            WindowManager windows = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
            Rect bounds = windows.getMaximumWindowMetrics().getBounds();
            out.put("window_bounds", bounds.width() + "x" + bounds.height());
        }
        return out;
    }

    private static JSONObject cameras(Context context) throws Exception {
        CameraManager manager = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no camera service");
        JSONArray list = new JSONArray();
        for (String id : manager.getCameraIdList()) {
            CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
            JSONObject item = new JSONObject();
            item.put("id", id);
            Integer facing = characteristics.get(CameraCharacteristics.LENS_FACING);
            item.put("facing", facing == null ? JSONObject.NULL
                    : facing == CameraCharacteristics.LENS_FACING_BACK ? "back"
                    : facing == CameraCharacteristics.LENS_FACING_FRONT ? "front" : "external");
            android.util.Size pixels =
                    characteristics.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE);
            item.put("sensor_pixel_array", pixels == null ? JSONObject.NULL : pixels.toString());
            android.util.SizeF physical =
                    characteristics.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE);
            item.put("sensor_physical_size", physical == null ? JSONObject.NULL : physical.toString());
            float[] focal = characteristics.get(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS);
            List<Double> focals = new ArrayList<>();
            if (focal != null) {
                for (float value : focal) focals.add((double) value);
            }
            item.put("focal_lengths", new JSONArray(focals));
            item.put("sensor_orientation", characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION));
            item.put("hardware_level", characteristics.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL));
            int[] capabilities =
                    characteristics.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES);
            item.put("capabilities", capabilities == null ? JSONObject.NULL : intArray(capabilities));
            item.put("physical_ids", new ArrayList<>(characteristics.getPhysicalCameraIds()));
            list.put(item);
        }
        return new JSONObject().put("count", list.length()).put("list", list);
    }

    private static JSONObject codecs() throws Exception {
        MediaCodecList all = new MediaCodecList(MediaCodecList.ALL_CODECS);
        JSONArray list = new JSONArray();
        for (android.media.MediaCodecInfo info : all.getCodecInfos()) {
            JSONObject item = new JSONObject();
            item.put("name", info.getName());
            if (Build.VERSION.SDK_INT >= 29) {
                item.put("canonical_name", info.getCanonicalName());
                item.put("is_software", info.isSoftwareOnly());
            }
            item.put("is_encoder", info.isEncoder());
            item.put("supported_types", stringArray(info.getSupportedTypes()));
            list.put(item);
        }
        return new JSONObject().put("count", list.length()).put("list", list);
    }

    private static JSONObject drm() throws Exception {
        JSONObject out = new JSONObject();
        try (MediaDrm widevine = new MediaDrm(WIDEVINE_UUID)) {
            out.put("scheme", "widevine");
            put(out, "vendor", () -> widevine.getPropertyString(MediaDrm.PROPERTY_VENDOR));
            put(out, "version", () -> widevine.getPropertyString(MediaDrm.PROPERTY_VERSION));
            put(out, "algorithms", () -> widevine.getPropertyString(MediaDrm.PROPERTY_ALGORITHMS));
            // securityLevel/systemId property keys are not public constants; the
            // literal keys still work on stock implementations and are guarded.
            put(out, "security_level", () -> widevine.getPropertyString("securityLevel"));
            put(out, "system_id", () -> widevine.getPropertyString("systemId"));
            put(out, "max_hdcp_level", widevine::getMaxHdcpLevel);
            put(out, "connected_hdcp_level", widevine::getConnectedHdcpLevel);
            put(out, "device_unique_id_sha256",
                    () -> Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                            .digest(widevine.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID))));
        }
        return out;
    }

    private static JSONObject features(Context context) throws Exception {
        PackageManager packages = context.getPackageManager();
        JSONArray list = new JSONArray();
        for (FeatureInfo feature : packages.getSystemAvailableFeatures()) {
            if (feature.name == null) continue;
            JSONObject item = new JSONObject();
            item.put("name", feature.name);
            String glEsVersion = feature.getGlEsVersion();
            if (glEsVersion != null && !glEsVersion.isEmpty()) {
                item.put("gl_es_version", glEsVersion);
            }
            list.put(item);
        }
        return new JSONObject().put("count", list.length()).put("list", list);
    }

    private static JSONObject inputDevices() throws Exception {
        JSONArray list = new JSONArray();
        for (int id : InputDevice.getDeviceIds()) {
            InputDevice device = InputDevice.getDevice(id);
            if (device == null) continue;
            JSONObject item = new JSONObject();
            item.put("id", id);
            item.put("name", device.getName());
            item.put("descriptor", device.getDescriptor());
            item.put("sources", device.getSources());
            item.put("keyboard_type", device.getKeyboardType());
            item.put("has_microphone", device.hasMicrophone());
            list.put(item);
        }
        return new JSONObject().put("count", list.length()).put("list", list);
    }

    private static JSONObject gnss(Context context) throws Exception {
        android.location.LocationManager manager =
                (android.location.LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no location service");
        JSONObject out = new JSONObject();
        out.put("providers", stringArray(manager.getAllProviders().toArray(new String[0])));
        if (Build.VERSION.SDK_INT >= 30) {
            put(out, "gnss_capabilities", () -> String.valueOf(manager.getGnssCapabilities()));
        }
        put(out, "gnss_year_of_hardware", () -> String.valueOf(manager.getGnssYearOfHardware()));
        if (Build.VERSION.SDK_INT >= 34) {
            put(out, "gnss_hardware_model_name", manager::getGnssHardwareModelName);
        }
        return out;
    }

    private static JSONObject memory(Context context) throws Exception {
        ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no activity manager");
        ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
        manager.getMemoryInfo(info);
        JSONObject out = new JSONObject();
        out.put("total_mem", info.totalMem);
        out.put("avail_mem", info.availMem);
        out.put("threshold", info.threshold);
        out.put("is_low_ram", manager.isLowRamDevice());
        out.put("large_memory_class", manager.getLargeMemoryClass());
        return out;
    }

    private static JSONObject storage(Context context) throws Exception {
        StorageManager manager = (StorageManager) context.getSystemService(Context.STORAGE_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no storage manager");
        JSONArray volumes = new JSONArray();
        for (StorageVolume volume : manager.getStorageVolumes()) {
            JSONObject item = new JSONObject();
            item.put("state", volume.getState());
            item.put("description", volume.getDescription(context));
            item.put("is_emulated", volume.isEmulated());
            item.put("is_removable", volume.isRemovable());
            item.put("is_primary", volume.isPrimary());
            item.put("uuid", volume.getUuid() == null ? JSONObject.NULL : volume.getUuid());
            if (Build.VERSION.SDK_INT >= 30) {
                put(item, "directory", () -> String.valueOf(volume.getDirectory()));
            }
            volumes.put(item);
        }
        return new JSONObject().put("volumes", volumes);
    }

    private static JSONObject power(Context context) throws Exception {
        JSONObject out = new JSONObject();
        PowerManager power = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (power != null) {
            out.put("is_power_save_mode", power.isPowerSaveMode());
            if (Build.VERSION.SDK_INT >= 29) {
                put(out, "thermal_status", power::getCurrentThermalStatus);
            }
            if (Build.VERSION.SDK_INT >= 30) {
                put(out, "thermal_headroom", () -> power.getThermalHeadroom(10));
            }
        }
        Intent battery = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            JSONObject batteryJson = new JSONObject();
            batteryJson.put("status", battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1));
            batteryJson.put("plugged", battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1));
            batteryJson.put("voltage_centivolts", battery.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1));
            batteryJson.put("temperature_deci_celsius", battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1));
            put(batteryJson, "technology", () -> battery.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY));
            BatteryManager manager = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
            if (manager != null) {
                batteryJson.put("charge_counter_micro_amp_hours",
                        manager.getLongProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER));
                put(batteryJson, "capacity_micro_amp_hours",
                        () -> manager.getLongProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY));
                put(batteryJson, "current_average_micro_amps",
                        () -> manager.getLongProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE));
            }
            out.put("battery", batteryJson);
        }
        return out;
    }

    private static JSONObject audio(Context context) throws Exception {
        AudioManager manager = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no audio service");
        JSONObject out = new JSONObject();
        put(out, "output_sample_rate", () -> manager.getProperty(AudioManager.PROPERTY_OUTPUT_SAMPLE_RATE));
        put(out, "output_frames_per_buffer",
                () -> manager.getProperty(AudioManager.PROPERTY_OUTPUT_FRAMES_PER_BUFFER));
        put(out, "unprocessed_supported",
                () -> manager.getProperty(AudioManager.PROPERTY_SUPPORT_AUDIO_SOURCE_UNPROCESSED));
        if (Build.VERSION.SDK_INT >= 31) {
            put(out, "encoded_surround_mode", manager::getEncodedSurroundMode);
        }
        put(out, "microphones", () -> {
            JSONArray list = new JSONArray();
            List<MicrophoneInfo> microphones = manager.getMicrophones();
            if (microphones != null) {
                for (MicrophoneInfo microphone : microphones) {
                    JSONObject item = new JSONObject();
                    item.put("description", microphone.getDescription());
                    item.put("type", microphone.getType());
                    item.put("address", microphone.getAddress());
                    list.put(item);
                }
            }
            return list;
        });
        return out;
    }

    private static JSONObject telephony(Context context) throws Exception {
        TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (manager == null) return new JSONObject().put("error", "no telephony service");
        JSONObject out = new JSONObject();
        out.put("phone_type", manager.getPhoneType());
        out.put("sim_state", manager.getSimState());
        if (Build.VERSION.SDK_INT >= 30) {
            put(out, "active_modem_count", manager::getActiveModemCount);
            put(out, "supported_modem_count", manager::getSupportedModemCount);
        }
        return out;
    }

    private static void putFile(JSONObject out, String key, String path) {
        put(out, key, () -> readFile(path));
    }

    private static String readFile(String path) throws Exception {
        try (FileInputStream input = new FileInputStream(path)) {
            return readAll(input);
        }
    }

    private static String readAll(InputStream input) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = input.read(chunk)) > 0) {
            buffer.write(chunk, 0, read);
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private static byte[] exec(String... command) throws Exception {
        Process process = new ProcessBuilder(command).start();
        try (InputStream output = process.getInputStream()) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = output.read(chunk)) > 0) {
                buffer.write(chunk, 0, read);
            }
            if (process.waitFor() != 0) {
                throw new IllegalStateException("command failed: " + command[0]);
            }
            return buffer.toByteArray();
        }
    }

    private static JSONArray stringArray(String[] values) {
        return new JSONArray(Arrays.asList(values));
    }

    private static JSONArray intArray(int[] values) {
        JSONArray array = new JSONArray();
        for (int value : values) {
            array.put(value);
        }
        return array;
    }
}
