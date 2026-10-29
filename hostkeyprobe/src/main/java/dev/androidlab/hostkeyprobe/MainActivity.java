package dev.androidlab.hostkeyprobe;

import android.app.Activity;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.AtomicFile;
import android.util.Base64;
import android.util.JsonReader;
import android.util.JsonToken;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public final class MainActivity extends Activity {
    private static final long TTL_MS = 120000;
    private static final String PACKAGE = "dev.androidlab.hostkeyprobe";
    private static final Set<String> RESPONSE_FIELDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("schema_version", "nonce_base64url", "payload_sha256",
            "subject_public_blob_base64url", "subject_spki_base64url", "authority_public_blob_base64url",
            "root_claim_base64url", "identity_claim_base64url", "signature_base64url", "signature_algorithm", "salt_length")));
    private TextView status;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        status = new TextView(this);
        status.setText("Host signatures only. Android TEE trust is unverified.");
        layout.addView(status);
        addButton(layout, "New challenge", this::newChallenge);
        addButton(layout, "Verify response", this::verifyResponse);
        setContentView(layout);
    }

    private void addButton(LinearLayout layout, String text, Runnable action) {
        Button button = new Button(this);
        button.setText(text);
        button.setOnClickListener(view -> action.run());
        layout.addView(button);
    }

    private void newChallenge() {
        try {
            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);
            String requestId = id();
            String encoded = encode(nonce);
            long now = System.currentTimeMillis();
            long expires = Math.addExact(now, TTL_MS);
            String payload = canonical(requestId, encoded, expires);
            JSONObject challenge = new JSONObject().put("schema_version", 1).put("request_id", requestId)
                    .put("nonce_base64url", encoded).put("payload_utf8", payload).put("created_at_ms", now)
                    .put("expires_at_ms", expires).put("elapsed_created_ms", SystemClock.elapsedRealtime())
                    .put("consumed", false);
            write("challenge.json", challenge);
            status.setText("Challenge ready: " + requestId);
        } catch (Exception error) { status.setText("Challenge failed: " + safeCode(error)); }
    }

    private void verifyResponse() {
        JSONObject result = new JSONObject();
        String outcome = "rejected";
        try {
            result.put("schema_version", 1).put("attempt_id", id()).put("origin", "untrusted_host_key_response")
                    .put("claimed_key_protection", "windows_vbs")
                    .put("external_root_authenticated", false).put("android_tee_verified", false)
                    .put("google_attestation_verified", false).put("android_verified_windows_claims", false);
            JSONObject challenge = read("challenge.json", 4096);
            String requestId = challenge.getString("request_id");
            require(requestId.matches("[a-f0-9]{32}"), "REQUEST_ID");
            result.put("request_id", requestId);
            require(!challenge.getBoolean("consumed"), "CHALLENGE_CONSUMED");
            long age = SystemClock.elapsedRealtime() - challenge.getLong("elapsed_created_ms");
            long wallAge = System.currentTimeMillis() - challenge.getLong("created_at_ms");
            require(age >= 0 && age <= TTL_MS && wallAge >= 0 && wallAge <= TTL_MS
                    && System.currentTimeMillis() <= challenge.getLong("expires_at_ms"), "CHALLENGE_EXPIRED");
            String nonce = challenge.getString("nonce_base64url");
            decode(nonce, 32, 32);
            String payload = canonical(requestId, nonce, challenge.getLong("expires_at_ms"));
            require(payload.equals(challenge.getString("payload_utf8")), "CHALLENGE_PAYLOAD");
            JSONObject response = read("response.json", 32768);
            require(response.length() == RESPONSE_FIELDS.size(), "RESPONSE_FIELDS");
            Iterator<String> keys = response.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                require(RESPONSE_FIELDS.contains(key), "RESPONSE_FIELDS");
                require((key.equals("schema_version") || key.equals("salt_length"))
                        ? response.get(key) instanceof Long : response.get(key) instanceof String, "RESPONSE_FIELD_TYPE");
            }
            require(response.getLong("schema_version") == 1L, "RESPONSE_SCHEMA");
            require(nonce.equals(response.getString("nonce_base64url")), "NONCE_MISMATCH");
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
            require(hash(payloadBytes).equals(response.getString("payload_sha256")), "PAYLOAD_MISMATCH");
            require(response.getString("signature_algorithm").equals("RSA-PSS-SHA256")
                    && response.getLong("salt_length") == 32L, "SIGNATURE_ALGORITHM");
            byte[] spki = decode(response.getString("subject_spki_base64url"), 200, 1024);
            RSAPublicKey subject = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
            require(subject.getModulus().bitLength() == 2048, "PUBLIC_KEY_SIZE");
            byte[] blob = decode(response.getString("subject_public_blob_base64url"), 24, 1024);
            require(publicBlobMatches(blob, subject), "PUBLIC_KEY_BINDING");
            decode(response.getString("authority_public_blob_base64url"), 24, 1024);
            decode(response.getString("root_claim_base64url"), 24, 16384);
            decode(response.getString("identity_claim_base64url"), 32, 16384);
            byte[] signature = decode(response.getString("signature_base64url"), 256, 256);
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS");
            verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            verifier.initVerify(subject);
            verifier.update(payloadBytes);
            require(verifier.verify(signature), "SIGNATURE_INVALID");
            challenge.put("consumed", true);
            write("challenge.json", challenge);
            result.put("signature_verified", true).put("nonce_matches", true).put("public_blob_matches_spki", true)
                    .put("challenge_consumed", true).put("payload_sha256", hash(payloadBytes))
                    .put("subject_spki_sha256", hash(spki)).put("challenge_age_ms", age);
            outcome = "verified_untrusted_host_signature";
        } catch (Exception error) {
            try { result.put("error_code", safeCode(error)); } catch (Exception ignored) { }
        }
        try {
            result.put("verification_state", outcome);
            write("result.json", result);
            status.setText(outcome.equals("rejected") ? "Rejected: " + result.optString("error_code")
                    : "Signature verified. Host and Android TEE trust remain unverified.");
        } catch (Exception error) { status.setText("Report failed: " + safeCode(error)); }
    }

    private static boolean publicBlobMatches(byte[] blob, RSAPublicKey key) throws Exception {
        ByteBuffer input = ByteBuffer.wrap(blob).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        require(blob.length >= 24 && input.getInt() == 0x31415352, "PUBLIC_BLOB_FORMAT");
        int bits = input.getInt(), exponentLength = input.getInt(), modulusLength = input.getInt();
        require(bits == 2048 && exponentLength > 0 && exponentLength <= 8 && modulusLength == 256
                && input.getInt() == 0 && input.getInt() == 0 && blob.length == 24 + exponentLength + modulusLength,
                "PUBLIC_BLOB_FORMAT");
        byte[] exponent = new byte[exponentLength], modulus = new byte[modulusLength];
        input.get(exponent); input.get(modulus);
        return key.getPublicExponent().equals(new java.math.BigInteger(1, exponent))
                && key.getModulus().equals(new java.math.BigInteger(1, modulus));
    }

    private JSONObject read(String name, int limit) throws Exception {
        AtomicFile file = new AtomicFile(new File(getFilesDir(), name));
        try (InputStream input = file.openRead(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[2048]; int count;
            while ((count = input.read(buffer)) != -1) {
                require(output.size() + count <= limit, "FILE_SIZE");
                output.write(buffer, 0, count);
            }
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(output.toByteArray())).toString();
            JSONObject parsed = new JSONObject();
            Set<String> seen = new HashSet<>();
            try (JsonReader reader = new JsonReader(new StringReader(text))) {
                reader.setLenient(false);
                reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    require(seen.add(key), "DUPLICATE_FIELD");
                    JsonToken token = reader.peek();
                    if (token == JsonToken.STRING) parsed.put(key, reader.nextString());
                    else if (token == JsonToken.BOOLEAN) parsed.put(key, reader.nextBoolean());
                    else if (token == JsonToken.NUMBER) {
                        String number = reader.nextString();
                        require(number.matches("-?(0|[1-9][0-9]*)"), "JSON_INTEGER_FORMAT");
                        parsed.put(key, Long.parseLong(number));
                    }
                    else throw new Exception("JSON_VALUE_TYPE");
                }
                reader.endObject();
                require(reader.peek() == JsonToken.END_DOCUMENT, "JSON_TRAILING_DATA");
            }
            return parsed;
        }
    }

    private void write(String name, JSONObject value) throws Exception {
        AtomicFile file = new AtomicFile(new File(getFilesDir(), name));
        FileOutputStream output = null;
        try {
            output = file.startWrite();
            output.write(value.toString().getBytes(StandardCharsets.UTF_8));
            file.finishWrite(output);
        } catch (Exception error) { if (output != null) file.failWrite(output); throw error; }
    }

    private static String canonical(String requestId, String nonce, long expires) {
        return "android-device-lab-hostkey-v1\n" + requestId + "\n" + nonce + "\n" + PACKAGE + "\n" + expires;
    }
    private static String id() { return UUID.randomUUID().toString().replace("-", ""); }
    private static String encode(byte[] bytes) { return Base64.encodeToString(bytes, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }
    private static byte[] decode(String value, int minimum, int maximum) throws Exception {
        require(value.length() <= maximum * 2 && value.matches("[A-Za-z0-9_-]+"), "BASE64_FORMAT");
        byte[] bytes = Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        require(bytes.length >= minimum && bytes.length <= maximum && encode(bytes).equals(value), "BASE64_CANONICAL");
        return bytes;
    }
    private static String hash(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder text = new StringBuilder(64);
        for (byte item : digest) text.append(String.format(java.util.Locale.ROOT, "%02x", item & 255));
        return text.toString();
    }
    private static void require(boolean condition, String code) throws Exception { if (!condition) throw new Exception(code); }
    private static String safeCode(Exception error) {
        String message = error.getMessage();
        return message != null && message.matches("[A-Z0-9_]{1,64}") ? message : "LOCAL_VERIFICATION_FAILED";
    }
}
