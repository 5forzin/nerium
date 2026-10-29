package dev.androidlab.hardwareprobe;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONObject;

/**
 * Runs one hardware snapshot inside a Firebase Test Lab instrumentation run.
 * Each section is streamed through logcat the moment it completes, so a
 * blocked call costs one section instead of the whole capture, and the
 * instrumentation keeps producing status output while it works (Test Lab's
 * runner kills quiet instruments).
 */
public final class SnapshotRunner extends Instrumentation {

    private static final String TAG = "HardwareSnapshotReport";

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        // The framework does not start the instrumentation by itself; a runner
        // that forgets this leaves `am instrument -w` waiting forever.
        start();
    }

    @Override
    public void onStart() {
        super.onStart();
        Bundle heartbeat = new Bundle();
        heartbeat.putString("progress", "starting");
        sendStatus(0, heartbeat);
        HardwareSnapshot.sink = (name, compactJson) -> {
            logChunked("SECTION " + name + " " + compactJson.length() + " bytes");
            logChunked(compactJson);
            Bundle status = new Bundle();
            status.putString("progress", name);
            sendStatus(0, status);
        };
        try {
            Context target = getTargetContext();
            JSONObject report = new HardwareSnapshot().collect(target);
            String json = report.toString(2);
            Log.i(TAG, "BEGIN_JSON");
            for (int start = 0; start < json.length(); start += 3000) {
                Log.i(TAG, json.substring(start, Math.min(json.length(), start + 3000)));
            }
            Log.i(TAG, "END_JSON");
            finish(0, new Bundle());
        } catch (Throwable error) {
            Log.e(TAG, "collection failed", error);
            Bundle results = new Bundle();
            results.putString("error", String.valueOf(error));
            finish(1, results);
        }
    }

    private static void logChunked(String message) {
        for (int start = 0; start < message.length(); start += 3000) {
            Log.i(TAG, message.substring(start, Math.min(message.length(), start + 3000)));
        }
    }
}
