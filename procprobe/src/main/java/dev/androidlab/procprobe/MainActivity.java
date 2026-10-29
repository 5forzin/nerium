package dev.androidlab.procprobe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class MainActivity extends Activity {
    static { System.loadLibrary("procinterfaceprobe"); }
    private static native String collectNative();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView output = new TextView(this);
        output.setTextSize(13);
        output.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        setContentView(scroll);
        new Thread(() -> {
            try {
                JSONObject report = new JSONObject(collectNative());
                JSONArray checks = report.getJSONArray("checks");
                int detected = 0, unavailable = 0;
                for (int i = 0; i < checks.length(); ++i) {
                    String status = checks.getJSONObject(i).getString("status");
                    if (status.equals("detected")) ++detected;
                    if (status.equals("unavailable")) ++unavailable;
                }
                report.put("schema_version", 1);
                report.put("summary", new JSONObject().put("detected", detected)
                        .put("unavailable", unavailable).put("total", checks.length()));
                String json = report.toString(2);
                Files.write(new File(getFilesDir(), "report.json").toPath(), json.getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> output.setText(json));
            } catch (Exception error) {
                runOnUiThread(() -> output.setText(error.toString()));
            }
        }, "proc-interface-probe").start();
    }
}
