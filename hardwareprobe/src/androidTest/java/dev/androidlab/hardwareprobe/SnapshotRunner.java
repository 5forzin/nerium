package dev.androidlab.hardwareprobe;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONObject;

/**
 * Runs one hardware snapshot inside a Firebase Test Lab instrumentation run
 * and streams the JSON through logcat in bounded chunks (Test Lab captures
 * logcat; app-private files are not directly downloadable from a remote
 * physical device).
 */
public final class SnapshotRunner extends Instrumentation {

    @Override
    public void onStart() {
        super.onStart();
        try {
            Context target = getTargetContext();
            JSONObject report = new HardwareSnapshot().collect(target);
            String json = report.toString(2);
            Log.i("HardwareSnapshotReport", "BEGIN_JSON");
            for (int start = 0; start < json.length(); start += 3000) {
                Log.i("HardwareSnapshotReport", json.substring(start, Math.min(json.length(), start + 3000)));
            }
            Log.i("HardwareSnapshotReport", "END_JSON");
            finish(0, new Bundle());
        } catch (Throwable error) {
            Log.e("HardwareSnapshotReport", "collection failed", error);
            Bundle results = new Bundle();
            results.putString("error", String.valueOf(error));
            finish(1, results);
        }
    }
}
