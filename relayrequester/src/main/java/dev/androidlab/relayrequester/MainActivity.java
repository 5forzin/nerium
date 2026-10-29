package dev.androidlab.relayrequester;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private TextView status;
    private RequesterClient client;
    private int generation;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        status = new TextView(this);
        status.setText("Stopped. Results describe the remote worker.");
        layout.addView(status);
        addButton(layout, "Run echo", () -> run("echo_sha256"));
        addButton(layout, "Run Integrity", () -> run("play_integrity"));
        addButton(layout, "Cancel", this::cancel);
        setContentView(layout);
    }

    private void addButton(LinearLayout layout, String label, Runnable action) {
        Button button = new Button(this);
        button.setText(label);
        button.setOnClickListener(view -> action.run());
        layout.addView(button);
    }

    private void run(String operation) {
        cancel();
        int current = ++generation;
        status.setText("Requesting remote worker...");
        client = new RequesterClient(getApplicationContext(), message -> runOnUiThread(() -> {
            if (current == generation) status.setText(message);
        }));
        client.start(operation);
    }

    private void cancel() {
        generation++;
        if (client != null) client.close();
        client = null;
        if (status != null) status.setText("Cancelled");
    }

    @Override protected void onStop() {
        cancel();
        super.onStop();
    }
}
