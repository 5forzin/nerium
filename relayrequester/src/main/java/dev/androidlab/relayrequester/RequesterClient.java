package dev.androidlab.relayrequester;

import android.content.Context;
import android.os.SystemClock;
import android.util.AtomicFile;
import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Explicit requests to the paired broker; verdicts belong to the remote worker. */
final class RequesterClient implements AutoCloseable {
    private static final int MAX_RESPONSE = 262144;
    private final Context context;
    private final Consumer<String> status;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private final Set<HttpsURLConnection> connections = ConcurrentHashMap.newKeySet();
    private volatile boolean closed;
    private Config config;
    private SSLContext tls;
    private long deadline;

    RequesterClient(Context context, Consumer<String> status) {
        this.context = context;
        this.status = status;
    }

    void start(String operation) {
        executor.execute(() -> {
            JSONObject report = new JSONObject();
            long started = SystemClock.elapsedRealtime();
            try {
                require(operation.equals("echo_sha256") || operation.equals("play_integrity"), "OPERATION");
                config = Config.load(new File(context.getFilesDir(), "requester-config.json"));
                tls = createTls(config);
                long remaining = config.expires - System.currentTimeMillis();
                require(remaining >= 30000, "SESSION_NEAR_EXPIRY");
                int timeout = (int) Math.min(120000, remaining);
                deadline = started + timeout;
                timer.schedule(() -> {
                    for (HttpsURLConnection connection : connections) connection.disconnect();
                }, Math.max(1, deadline - SystemClock.elapsedRealtime()), TimeUnit.MILLISECONDS);
                String id = UUID.randomUUID().toString().replace("-", "");
                byte[] challengeBytes = new byte[32];
                new SecureRandom().nextBytes(challengeBytes);
                String challenge = Base64.encodeToString(challengeBytes, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
                String challengeHash = hash(challengeBytes);
                String canonical = "r1\n" + config.pairId + "\n" + id + "\n" + operation + "\n" + challenge + "\n" + timeout;
                String requestHash = hash(canonical.getBytes(StandardCharsets.UTF_8));
                JSONObject body = new JSONObject().put("schema_version", 1).put("request_id", id)
                        .put("operation", operation).put("challenge_base64url", challenge).put("timeout_ms", timeout);
                String serialized = body.toString();
                require(serialized.getBytes(StandardCharsets.UTF_8).length <= 4096, "REQUEST_SIZE");
                report.put("schema_version", 1).put("request_id", id).put("request_sha256", requestHash)
                        .put("challenge_sha256", challengeHash).put("operation", operation)
                        .put("origin", "cooperative_remote_worker").put("requester_integrity_verified", false)
                        .put("verification_state", "pending");
                Response receipt;
                long backoff = 250;
                while (true) {
                    ensureActive();
                    try { receipt = request("POST", "/v1/requests", serialized); break; }
                    catch (javax.net.ssl.SSLException error) { throw new Failure("TLS_REJECTED"); }
                    catch (java.io.IOException error) { pause(backoff); backoff = Math.min(1000, backoff * 2); }
                }
                require(receipt.code == 202, receipt.code == 409 ? "REQUEST_CONFLICT" : "RECEIPT_HTTP_REJECTED");
                validateBinding(receipt.body, id, requestHash, operation, challengeHash);
                JSONObject terminal;
                backoff = 250;
                while (true) {
                    ensureActive();
                    try {
                        Response response = request("GET", "/v1/requests/" + id, null);
                        require(response.code == 200, "POLL_HTTP_REJECTED");
                        validateBinding(response.body, id, requestHash, operation, challengeHash);
                        String state = response.body.getString("state");
                        require(state.equals("accepted") || state.equals("running") || state.equals("completed")
                                || state.equals("failed") || state.equals("expired"), "RESPONSE_STATE");
                        if (state.equals("completed") || state.equals("failed") || state.equals("expired")) {
                            terminal = response.body;
                            break;
                        }
                    } catch (javax.net.ssl.SSLException error) { throw new Failure("TLS_REJECTED"); }
                    catch (java.io.IOException error) {
                        // Retain the same request and monotonic deadline after a transport interruption.
                    }
                    pause(backoff);
                    backoff = Math.min(1000, backoff * 2);
                }
                require(terminal.getString("state").equals("completed"),
                        terminal.getString("state").equals("expired") ? "REMOTE_EXPIRED" : "REMOTE_FAILED");
                JSONObject result = terminal.getJSONObject("result");
                validateBinding(result, id, requestHash, operation, challengeHash);
                require(result.getString("worker_package").equals("dev.androidlab.relayworker"), "WORKER_PACKAGE");
                require(!result.has("token") && !terminal.has("token"), "RAW_TOKEN_FORBIDDEN");
                if (operation.equals("echo_sha256")) {
                    require(result.getString("challenge_sha256").equals(challengeHash), "ECHO_HASH");
                } else {
                    JSONObject binding = result.getJSONObject("request_binding");
                    require(Boolean.TRUE.equals(binding.get("package_matches"))
                            && Boolean.TRUE.equals(binding.get("nonce_bytes_match"))
                            && Boolean.TRUE.equals(binding.get("timestamp_in_window")), "INTEGRITY_BINDING");
                    report.put("request_binding", new JSONObject().put("package_matches", true)
                            .put("nonce_bytes_match", true).put("timestamp_in_window", true));
                    report.put("worker_verdict", sanitizedVerdict(result.getJSONObject("worker_verdict")));
                }
                for (String metric : new String[] {"broker_observed_elapsed_ms", "execution_elapsed_ms", "completed_at_ms"}) {
                    if (result.has(metric)) report.put(metric, integer(result, metric));
                }
                report.put("worker_package", "dev.androidlab.relayworker")
                        .put("verification_state", "verified_remote_result");
                ensureActive();
                save(report.put("client_elapsed_ms", SystemClock.elapsedRealtime() - started));
                status.accept(operation.equals("echo_sha256") ? "Remote worker echo verified. Local integrity unchanged."
                        : "Remote worker Integrity verified. Local integrity unchanged.\n" + report.getJSONObject("worker_verdict").toString(2));
            } catch (Exception error) {
                if (!closed) {
                    String code = error instanceof Failure ? ((Failure) error).code : "REQUEST_FAILED";
                    try {
                        report.put("schema_version", 1).put("origin", "cooperative_remote_worker")
                                .put("requester_integrity_verified", false).put("verification_state", "failed")
                                .put("error_code", code).put("client_elapsed_ms", SystemClock.elapsedRealtime() - started);
                        save(report);
                    } catch (Exception ignored) { }
                    status.accept("Failed: " + code);
                }
            } finally { close(); }
        });
    }

    private static void validateBinding(JSONObject value, String id, String requestHash, String operation,
                                        String challengeHash) throws Exception {
        require(value.getString("request_id").equals(id) && value.getString("request_sha256").equals(requestHash)
                && value.getString("operation").equals(operation)
                && value.getString("challenge_sha256").equals(challengeHash)
                && value.getString("origin").equals("cooperative_remote_worker")
                && Boolean.FALSE.equals(value.get("requester_integrity_verified")), "RESPONSE_BINDING");
    }

    private static JSONObject sanitizedVerdict(JSONObject source) throws Exception {
        JSONObject result = new JSONObject();
        JSONObject app = source.getJSONObject("app_integrity");
        if (app != null) {
            JSONObject clean = new JSONObject();
            copyLabel(app, clean, "appRecognitionVerdict");
            result.put("app_integrity", clean);
        }
        JSONObject device = source.getJSONObject("device_integrity");
        JSONObject cleanDevice = new JSONObject();
        if (device.has("deviceRecognitionVerdict")) {
            org.json.JSONArray labels = device.getJSONArray("deviceRecognitionVerdict");
            require(labels.length() <= 16, "VERDICT_SIZE");
            org.json.JSONArray clean = new org.json.JSONArray();
            for (int i = 0; i < labels.length(); i++) {
                String label = labels.getString(i);
                require(label.matches("[A-Z][A-Z0-9_]{0,63}"), "VERDICT_LABEL");
                clean.put(label);
            }
            cleanDevice.put("deviceRecognitionVerdict", clean);
        }
        result.put("device_integrity", cleanDevice);
        JSONObject account = source.getJSONObject("account_details");
        if (account != null) {
            JSONObject clean = new JSONObject();
            copyLabel(account, clean, "appLicensingVerdict");
            result.put("account_details", clean);
        }
        return result;
    }

    private static void copyLabel(JSONObject source, JSONObject destination, String key) throws Exception {
        if (!source.has(key)) return;
        String label = source.getString(key);
        require(label.matches("[A-Z][A-Z0-9_]{0,63}"), "VERDICT_LABEL");
        destination.put(key, label);
    }

    private Response request(String method, String path, String body) throws Exception {
        ensureActive();
        HttpsURLConnection connection = (HttpsURLConnection) new URL(config.url + path).openConnection();
        connection.setSSLSocketFactory(tls.getSocketFactory());
        connection.setInstanceFollowRedirects(false);
        connection.setUseCaches(false);
        int timeout = (int) Math.max(1, Math.min(10000, deadline - SystemClock.elapsedRealtime()));
        connection.setConnectTimeout(timeout);
        connection.setReadTimeout(timeout);
        connection.setRequestMethod(method);
        connection.setRequestProperty("Authorization", "Bearer " + config.bearer);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Accept-Encoding", "identity");
        connections.add(connection);
        try {
            ensureActive();
            if (body != null) {
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                connection.setFixedLengthStreamingMode(bytes.length);
                try (java.io.OutputStream output = connection.getOutputStream()) { output.write(bytes); }
            }
            int code = connection.getResponseCode();
            require(code >= 200 && code < 300, code == 409 ? "REQUEST_CONFLICT" : "HTTP_REJECTED");
            try (InputStream input = connection.getInputStream(); ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    ensureActive();
                    require(bytes.size() + count <= MAX_RESPONSE, "RESPONSE_SIZE");
                    bytes.write(buffer, 0, count);
                }
                ensureActive();
                return new Response(code, new JSONObject(bytes.toString(StandardCharsets.UTF_8.name())));
            }
        } finally { connections.remove(connection); connection.disconnect(); }
    }

    private static SSLContext createTls(Config config) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(config.certificate.getBytes(StandardCharsets.US_ASCII)));
        certificate.checkValidity();
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null);
        store.setCertificateEntry("paired-broker", certificate);
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(store);
        X509TrustManager delegate = null;
        for (TrustManager manager : managers.getTrustManagers()) if (manager instanceof X509TrustManager) delegate = (X509TrustManager) manager;
        require(delegate != null, "TLS_TRUST_MANAGER");
        final X509TrustManager trusted = delegate;
        byte[] expected = unhex(config.pin);
        X509TrustManager pinned = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("Client certificates are not used");
            }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                trusted.checkServerTrusted(chain, authType);
                if (chain.length == 0) throw new CertificateException("Empty certificate chain");
                chain[0].checkValidity();
                try {
                    byte[] actual = MessageDigest.getInstance("SHA-256").digest(chain[0].getPublicKey().getEncoded());
                    if (!MessageDigest.isEqual(expected, actual)) throw new CertificateException("Broker pin mismatch");
                } catch (java.security.NoSuchAlgorithmException error) { throw new CertificateException("SHA256 unavailable"); }
            }
            @Override public X509Certificate[] getAcceptedIssuers() { return trusted.getAcceptedIssuers(); }
        };
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, new TrustManager[] {pinned}, null);
        return tls;
    }

    private void ensureActive() throws Failure {
        require(!closed && !Thread.currentThread().isInterrupted(), "CANCELLED");
        require(SystemClock.elapsedRealtime() < deadline, "REQUEST_TIMEOUT");
    }

    private void pause(long millis) throws Exception {
        ensureActive();
        Thread.sleep(Math.min(millis, Math.max(1, deadline - SystemClock.elapsedRealtime())));
    }

    private synchronized void save(JSONObject report) throws Exception {
        require(!closed, "CANCELLED");
        byte[] bytes = report.toString(2).getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= 16384, "REPORT_SIZE");
        AtomicFile file = new AtomicFile(new File(context.getFilesDir(), "requester-result.json"));
        FileOutputStream output = null;
        try { output = file.startWrite(); output.write(bytes); file.finishWrite(output); }
        catch (Exception error) { if (output != null) file.failWrite(output); throw error; }
    }

    @Override public synchronized void close() {
        closed = true;
        for (HttpsURLConnection connection : connections) connection.disconnect();
        connections.clear();
        if (config != null) config.bearer = null;
        executor.shutdownNow();
        timer.shutdownNow();
    }

    private static long integer(JSONObject source, String key) throws Exception {
        Object value = source.get(key);
        require(value instanceof Integer || value instanceof Long, "INTEGER_REQUIRED");
        long number = ((Number) value).longValue();
        require(number >= 0 && number <= 9007199254740991L, "INTEGER_RANGE");
        return number;
    }
    private static String hash(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder hex = new StringBuilder();
        for (byte value : digest) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return hex.toString();
    }
    private static byte[] unhex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
        return bytes;
    }
    private static void require(boolean condition, String code) throws Failure { if (!condition) throw new Failure(code); }
    private static final class Failure extends Exception {
        final String code;
        Failure(String code) { super(code); this.code = code; }
    }
    private static final class Response {
        final int code;
        final JSONObject body;
        Response(int code, JSONObject body) { this.code = code; this.body = body; }
    }
    private static final class Config {
        String pairId, url, certificate, pin, bearer;
        long expires;
        static Config load(File file) throws Exception {
            require(file.isFile() && file.length() > 0 && file.length() <= 32768, "CONFIG_SIZE");
            JSONObject value = new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
            require(integer(value, "schema_version") == 1, "CONFIG_SCHEMA");
            Config config = new Config();
            config.pairId = value.getString("pair_id");
            config.url = value.getString("broker_url");
            config.certificate = value.getString("server_certificate_pem");
            config.pin = value.getString("server_spki_sha256");
            config.bearer = value.getString("bearer_token");
            config.expires = integer(value, "expires_at_ms");
            require(config.pairId.matches("[a-f0-9]{32}") && config.pin.matches("[a-f0-9]{64}")
                    && config.url.matches("https://127\\.0\\.0\\.1:[0-9]{1,5}") && config.bearer.matches("[A-Za-z0-9_-]{43}"), "CONFIG_FORMAT");
            URL url = new URL(config.url);
            require(url.getPort() >= 1 && url.getPort() <= 65535, "CONFIG_PORT");
            byte[] bearer = Base64.decode(config.bearer, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            require(bearer.length == 32 && config.bearer.equals(Base64.encodeToString(bearer,
                    Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING)), "CONFIG_BEARER");
            long remaining = config.expires - System.currentTimeMillis();
            require(remaining > 0 && remaining <= 1800000, "CONFIG_TTL");
            return config;
        }
    }
}
