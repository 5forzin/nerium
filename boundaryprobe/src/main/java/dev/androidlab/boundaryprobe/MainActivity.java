package dev.androidlab.boundaryprobe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;
import org.json.JSONObject;

public final class MainActivity extends Activity {
    static { System.loadLibrary("boundaryprobe"); }
    private static native String collectNative();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView output = new TextView(this);
        output.setTextSize(13);
        output.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        setContentView(scroll);
        String suppliedId = getIntent().getStringExtra("request_id");
        String requestId = suppliedId == null ? UUID.randomUUID().toString() : suppliedId;
        new Thread(() -> {
            try {
                JSONObject report = new JSONObject(collectNative());
                report.put("request_id", requestId);
                String json = report.toString(2);
                Files.write(new File(getFilesDir(), "report.json").toPath(), json.getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> output.setText(json));
            } catch (Exception error) {
                runOnUiThread(() -> output.setText(error.toString()));
            }
        }, "boundary-probe").start();
    }
}
