package dev.androidlab.attestationprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView output = new TextView(this);
        output.setPadding(32, 64, 32, 32);
        output.setTextSize(14);
        output.setTextIsSelectable(true);
        output.setTypeface(android.graphics.Typeface.MONOSPACE);
        output.setText(R.string.running);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        setContentView(scroll);
        worker.execute(() -> {
            try {
                String supplied = getIntent().getStringExtra("challenge_base64");
                byte[] challenge = supplied == null ? null : Base64.decode(supplied, Base64.DEFAULT);
                if (challenge != null && challenge.length != 32) {
                    throw new IllegalArgumentException("Expected a 32-byte external challenge");
                }
                String json = new AttestationProbe().collect(this, challenge).toString(2);
                Files.write(new File(getFilesDir(), "report.json").toPath(), json.getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> { if (!isDestroyed()) output.setText(json); });
            } catch (Exception error) {
                runOnUiThread(() -> { if (!isDestroyed()) output.setText(getString(R.string.failed, error.toString())); });
            }
        });
    }

    @Override public void onDestroy() {
        worker.shutdown();
        super.onDestroy();
    }
}
