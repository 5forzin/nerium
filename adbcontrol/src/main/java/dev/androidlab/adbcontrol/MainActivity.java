package dev.androidlab.adbcontrol;

import android.Manifest;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public final class MainActivity extends Activity {
    static final String PREFS = "recovery";
    static final String ACTION_START = "dev.androidlab.adbcontrol.START";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setPadding(32, 64, 32, 32);
        view.setTextSize(16);
        setContentView(view);

        if (!ACTION_START.equals(getIntent().getAction())) {
            view.setText("Start this lab test from the host.");
            return;
        }
        boolean dryRun = getIntent().getBooleanExtra("dry_run", false);
        int restoreSeconds = getIntent().getIntExtra("restore_seconds", dryRun ? 15 : 180);
        int scanDelaySeconds = getIntent().getIntExtra("scan_delay_seconds", 15);
        if (restoreSeconds < (dryRun ? 10 : 90) || restoreSeconds > 600 ||
                (!dryRun && (scanDelaySeconds < 5 || scanDelaySeconds > 60 || scanDelaySeconds + 30 >= restoreSeconds))) {
            view.setText("Invalid timing parameters.");
            return;
        }
        if (checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS) != PackageManager.PERMISSION_GRANTED) {
            view.setText("WRITE_SECURE_SETTINGS is not granted.");
            record(this, "permission_missing", dryRun);
            return;
        }
        int originalAdb = Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, -1);
        int wifiAdb = Settings.Global.getInt(getContentResolver(), "adb_wifi_enabled", -1);
        if (originalAdb != 1 || wifiAdb != 0) {
            view.setText("Expected USB ADB on and wireless ADB off.");
            record(this, "unexpected_baseline", dryRun);
            return;
        }

        if (!getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putInt("original_adb", originalAdb).putBoolean("dry_run", dryRun).commit()) {
            view.setText("Could not store the recovery state.");
            return;
        }
        PendingIntent recovery = PendingIntent.getBroadcast(this, 0,
                new Intent(this, RestoreReceiver.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        AlarmManager alarm = (AlarmManager) getSystemService(ALARM_SERVICE);
        alarm.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + restoreSeconds * 1000L, recovery);
        record(this, "recovery_armed", dryRun);
        if (dryRun) {
            view.setText("Recovery timer test armed.");
            return;
        }

        if (!Settings.Global.putInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0)) {
            view.setText("Could not disable USB ADB.");
            record(this, "disable_failed", false);
            return;
        }
        record(this, "adb_disable_requested", false);
        view.setText("ADB is off. Duck Detector starts shortly; ADB will return automatically.");
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            record(this, "before_duck_launch", false);
            try {
                Intent duck = new Intent().setClassName("com.eltavine.duckdetector", "android.app.NativeActivity");
                startActivity(duck);
                record(this, "duck_launch_requested", false);
            } catch (Exception error) {
                record(this, "duck_launch_failed_" + error.getClass().getSimpleName(), false);
            }
        }, scanDelaySeconds * 1000L);
    }

    static void record(Context context, String event, boolean dryRun) {
        try {
            JSONObject item = new JSONObject();
            item.put("event", event);
            item.put("elapsed_realtime_ms", SystemClock.elapsedRealtime());
            item.put("wall_time_ms", System.currentTimeMillis());
            item.put("dry_run", dryRun);
            item.put("adb_enabled", Settings.Global.getInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, -1));
            item.put("adb_wifi_enabled", Settings.Global.getInt(context.getContentResolver(), "adb_wifi_enabled", -1));
            item.put("adbd_socket_visible", new File("/dev/socket/adbd").exists());
            item.put("adbd_service", property("init.svc.adbd"));
            item.put("usb_config", property("persist.sys.usb.config"));
            try (FileWriter writer = new FileWriter(new File(context.getFilesDir(), "events.jsonl"), true)) {
                writer.write(item.toString());
                writer.write('\n');
            }
        } catch (Exception ignored) {
            // The recovery alarm must not depend on diagnostic storage.
        }
    }

    private static String property(String name) {
        try {
            Process process = new ProcessBuilder("/system/bin/getprop", name).start();
            if (!process.waitFor(2, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                return "unavailable";
            }
            return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (Exception error) {
            return "unavailable";
        }
    }
}
