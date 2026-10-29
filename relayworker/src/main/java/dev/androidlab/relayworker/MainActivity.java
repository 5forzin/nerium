package dev.androidlab.relayworker;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private TextView status;
    private RelayWorker worker;
    private boolean stopped;
    private int generation;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        status = new TextView(this);
        status.setText("Stopped");
        Button start = new Button(this);
        start.setText("Start");
        start.setOnClickListener(view -> startWorker());
        Button stop = new Button(this);
        stop.setText("Stop");
        stop.setOnClickListener(view -> stopWorker());
        layout.addView(status);
        layout.addView(start);
        layout.addView(stop);
        setContentView(layout);
        if (getIntent().getBooleanExtra("auto_start", false)) startWorker();
    }

    private void startWorker() {
        if (worker != null) return;
        stopped = false;
        int currentGeneration = ++generation;
        worker = new RelayWorker(getApplicationContext(), message -> runOnUiThread(() -> {
            if (!stopped && currentGeneration == generation) status.setText(message);
        }));
        worker.start();
    }

    private void stopWorker() {
        stopped = true;
        generation++;
        if (worker != null) worker.close();
        worker = null;
        status.setText("Stopped");
    }

    @Override protected void onStop() {
        stopWorker();
        super.onStop();
    }
}
