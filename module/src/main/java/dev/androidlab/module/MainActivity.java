package dev.androidlab.module;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 80, 48, 48);
        TextView title = new TextView(this);
        title.setText(R.string.app_name);
        title.setTextSize(26);
        layout.addView(title);
        TextView body = new TextView(this);
        body.setText(R.string.module_instructions);
        body.setTextSize(16);
        body.setPadding(0, 28, 0, 0);
        layout.addView(body);
        setContentView(layout);
    }
}
