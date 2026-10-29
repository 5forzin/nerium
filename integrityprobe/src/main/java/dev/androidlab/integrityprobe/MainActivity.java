package dev.androidlab.integrityprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;

import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityServiceException;
import com.google.android.play.core.integrity.IntegrityTokenRequest;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class MainActivity extends Activity {
    private TextView output;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        output = new TextView(this);
        output.setPadding(32, 64, 32, 32);
        output.setTextSize(16);
        output.setText("Requesting Play Integrity token...");
        setContentView(output);

        String nonce = getIntent().getStringExtra("nonce_base64url");
        long projectNumber = getIntent().getLongExtra("cloud_project_number", 0);
        if (projectNumber <= 0 || nonce == null || !validNonce(nonce)) {
            writeResult("invalid_request", projectNumber, nonce, null, null);
            return;
        }

        IntegrityTokenRequest request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(projectNumber)
                .build();
        IntegrityManagerFactory.create(getApplicationContext())
                .requestIntegrityToken(request)
                .addOnCompleteListener(task -> {
                    if (task.isSuccessful()) {
                        String token = task.getResult().token();
                        try {
                            Files.write(new File(getFilesDir(), "token.txt").toPath(),
                                    token.getBytes(StandardCharsets.UTF_8));
                            writeResult("token_received", projectNumber, nonce, token.length(), null);
                        } catch (Exception error) {
                            writeResult("storage_error", projectNumber, nonce, null, null);
                        }
                    } else {
                        Exception error = task.getException();
                        Integer errorCode = error instanceof IntegrityServiceException
                                ? ((IntegrityServiceException) error).getErrorCode() : null;
                        writeResult("request_failed", projectNumber, nonce, null, errorCode);
                    }
                });
    }

    private boolean validNonce(String nonce) {
        try {
            return Base64.decode(nonce, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP).length == 32;
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private void writeResult(String status, long projectNumber, String nonce,
                             Integer tokenLength, Integer errorCode) {
        try {
            JSONObject result = new JSONObject();
            result.put("schema_version", 1);
            result.put("captured_at_ms", System.currentTimeMillis());
            result.put("package", getPackageName());
            result.put("status", status);
            result.put("cloud_project_number", projectNumber);
            result.put("nonce_base64url", nonce);
            if (tokenLength != null) result.put("token_length", tokenLength);
            if (errorCode != null) result.put("error_code", errorCode);
            Files.write(new File(getFilesDir(), "report.json").toPath(),
                    result.toString(2).getBytes(StandardCharsets.UTF_8));
            runOnUiThread(() -> output.setText(status + (errorCode == null ? "" : " (" + errorCode + ")")));
        } catch (Exception error) {
            runOnUiThread(() -> output.setText("Could not save the probe result."));
        }
    }
}
