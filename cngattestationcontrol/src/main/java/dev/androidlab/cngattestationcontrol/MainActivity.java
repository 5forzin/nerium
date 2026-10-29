package dev.androidlab.cngattestationcontrol;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView output = new TextView(this);
        output.setPadding(32, 64, 32, 32);
        output.setText(R.string.running);
        setContentView(output);
        String supplied = getIntent().getStringExtra("challenge_base64");
        worker.execute(() -> {
            try {
                boolean complete = new AttestationControl().collect(this, supplied);
                runOnUiThread(() -> {
                    if (!isDestroyed()) output.setText(complete ? R.string.complete : R.string.failed);
                });
            } catch (Exception error) {
                runOnUiThread(() -> { if (!isDestroyed()) output.setText(R.string.write_failed); });
            }
        });
    }

    @Override public void onDestroy() {
        worker.shutdown();
        super.onDestroy();
    }
}
