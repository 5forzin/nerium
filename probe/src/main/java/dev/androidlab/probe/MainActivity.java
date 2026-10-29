package dev.androidlab.probe;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private TextView output;
    private Button run;
    private Button share;
    private String currentReport;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(36, 72, 36, 40);
        TextView title = new TextView(this);
        title.setText(R.string.app_name);
        title.setTextSize(26);
        layout.addView(title);
        run = new Button(this);
        run.setText(R.string.run_checks);
        run.setOnClickListener(view -> collect());
        layout.addView(run);
        share = new Button(this);
        share.setText(R.string.share_json);
        share.setEnabled(false);
        share.setOnClickListener(view -> startActivity(Intent.createChooser(
                new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, currentReport), getString(R.string.share_report))));
        layout.addView(share);
        ScrollView scroll = new ScrollView(this);
        output = new TextView(this);
        output.setTextSize(13);
        output.setTextIsSelectable(true);
        output.setTypeface(android.graphics.Typeface.MONOSPACE);
        scroll.addView(output);
        layout.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(layout);
        collect();
    }

    private void collect() {
        run.setEnabled(false);
        share.setEnabled(false);
        output.setText(R.string.running_checks);
        worker.execute(() -> {
            try {
                JSONObject report = new Probe().collect(getApplicationContext());
                String json = report.toString(2);
                Files.write(new File(getFilesDir(), "report.json").toPath(), json.getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    currentReport = json;
                    output.setText(json);
                    run.setEnabled(true);
                    share.setEnabled(true);
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    output.setText(getString(R.string.collection_failed, error.toString()));
                    run.setEnabled(true);
                });
            }
        });
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
