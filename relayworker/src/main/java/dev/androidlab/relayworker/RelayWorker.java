package dev.androidlab.relayworker;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.SystemClock;
import android.util.Base64;
import android.util.AtomicFile;

import com.google.android.gms.tasks.Task;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityServiceException;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.net.ssl.HttpsURLConnection;

/** Foreground-only cooperative executor. Results describe this APK's environment. */
final class RelayWorker implements AutoCloseable {
    private static final int MAX_RESPONSE = 262144;
    private static final int MAX_TOKEN = 32768;
    private static final long LEASE_MS = 90000;
    private final Context context;
    private final Consumer<String> status;
    private final ExecutorService transport = Executors.newSingleThreadExecutor();
    private final ExecutorService execution = Executors.newSingleThreadExecutor();
    private final Set<HttpsURLConnection> connections = ConcurrentHashMap.newKeySet();
    private final Set<String> queued = ConcurrentHashMap.newKeySet();
    private final LinkedHashSet<String> terminalIds = new LinkedHashSet<>();
    private long streamAttempts, streamConnections, eventCount, pollCount;
    private long lastEventAtMs, lastPollAtMs;
    private int lastHttpStatus;
    private String lastTransportError = "NONE";
    private final long transportStartedAtMs = System.currentTimeMillis();
    private volatile boolean closed;
    private volatile String idToken;
    private volatile ServerClock serverClock;
    private Config config;

    RelayWorker(Context context, Consumer<String> status) {
        this.context = context;
        this.status = status;
    }

    void start() {
        transport.execute(() -> {
            try {
                config = Config.load(new File(context.getFilesDir(), "relay-config.json"));
                authenticate();
                status.accept("Connected. Results describe this worker.");
                while (active()) {
                    try {
                        poll();
                        stream();
                    } catch (Exception error) {
                        transportFailure(error);
                        if (isAuthenticationFailure(error)) { stopForAuthentication(); break; }
                        if (active()) status.accept("Reconnecting (" + safeClass(error) + ")");
                    }
                    pause(2000);
                }
                if (!closed) status.accept("Session expired");
            } catch (Throwable error) {
                transportFailure(error);
                if (!closed) status.accept("Stopped (" + safeClass(error) + ")");
            } finally {
                close();
            }
        });
    }

    private boolean active() {
        ServerClock clock = serverClock;
        long now = clock == null ? System.currentTimeMillis() : clock.now();
        return !closed && config != null && now < config.expires;
    }

    private void authenticate() throws Exception {
        JSONObject request = new JSONObject().put("token", config.customToken)
                .put("returnSecureToken", true);
        Response response = request("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key="
                + config.apiKey, "POST", request.toString(), null, false);
        config.customToken = null;
        require(response.code == 200, "AUTH_FAILED");
        JSONObject body = new JSONObject(response.body);
        String token = body.getString("idToken");
        require(token.length() > 0 && token.length() <= MAX_TOKEN, "AUTH_TOKEN_SIZE");
        Response account = request("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key="
                + config.apiKey, "POST", new JSONObject().put("idToken", token).toString(), null, false);
        require(account.code == 200, "AUTH_LOOKUP_FAILED");
        org.json.JSONArray users = new JSONObject(account.body).getJSONArray("users");
        require(users.length() == 1 && config.uid.equals(users.getJSONObject(0).getString("localId")),
                "AUTH_UID_MISMATCH");
        long lifetime = Long.parseLong(body.getString("expiresIn"));
        require(lifetime > 0, "AUTH_EXPIRY");
        // A refresh token may be returned by Identity Toolkit; it is never retained.
        config.expires = Math.min(config.expires, System.currentTimeMillis() + lifetime * 1000 - 10000);
        idToken = token;
    }

    private String path(String collection) {
        return "/relay/v1/" + collection + "/" + config.uid + "/" + config.sid;
    }

    private String databaseUrl(String path) {
        return config.database + path + ".json?auth=" + idToken;
    }

    private void poll() throws Exception {
        if (!active()) return;
        synchronized (this) {
            pollCount++;
            lastPollAtMs = System.currentTimeMillis();
            writeTransport();
        }
        Response response = request(databaseUrl(path("inboxes")), "GET", null, null, false);
        require(response.code == 200, "POLL_FAILED");
        if ("null".equals(response.body.trim())) return;
        JSONObject jobs = new JSONObject(response.body);
        require(jobs.length() <= 256, "INBOX_TOO_LARGE");
        List<String> ids = new ArrayList<>();
        Iterator<String> iterator = jobs.keys();
        while (iterator.hasNext()) ids.add(iterator.next());
        Collections.sort(ids);
        for (String id : ids) enqueue(id);
    }

    private void enqueue(String id) {
        if (!active() || !id.matches("[a-f0-9]{32}") || terminalSeen(id)
                || queued.size() >= 256 || !queued.add(id)) return;
        try {
            execution.execute(() -> {
                try { execute(id); }
                catch (Exception error) {
                    if (isAuthenticationFailure(error)) { stopForAuthentication(); return; }
                    if (error instanceof ProtocolFailure) {
                        String code = ((ProtocolFailure) error).code;
                        if (code.equals("SERVER_DATE_MISSING") || code.equals("LEASE_WINDOW_INSUFFICIENT")
                                || code.startsWith("LEASE_RESPONSE_"))
                            writeFailure(code, 0, "LOCAL", "execution");
                    }
                    if (active()) status.accept("Job unavailable (" + safeClass(error) + ")");
                } finally { queued.remove(id); }
            });
        } catch (RuntimeException error) { queued.remove(id); }
    }

    private void stream() throws Exception {
        HttpsURLConnection connection = openStream(databaseUrl(path("inboxes")));
        long deadline = SystemClock.elapsedRealtime() + 20000;
        try {
            int streamCode = connection.getResponseCode();
            rejectAuthentication(streamCode, "GET", "stream");
            require(streamCode == 200, "STREAM_FAILED");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    connection.getInputStream(), StandardCharsets.UTF_8))) {
                String event = "";
                StringBuilder data = new StringBuilder();
                while (active() && SystemClock.elapsedRealtime() < deadline) {
                    String line = boundedLine(reader);
                    if (line == null) break;
                    if (line.isEmpty()) {
                        if ("cancel".equals(event) || "auth_revoked".equals(event)) {
                            writeFailure("STREAM_AUTH_REJECTED", streamCode, "GET", "stream");
                            throw new ProtocolFailure("STREAM_AUTH_REJECTED");
                        }
                        if (("put".equals(event) || "patch".equals(event)) && data.length() > 0) {
                            JSONObject frame = new JSONObject(data.toString());
                            require(frame.has("path") && frame.get("path") instanceof String
                                    && frame.has("data"), "STREAM_EVENT_FORMAT");
                            synchronized (this) {
                                eventCount++;
                                lastEventAtMs = System.currentTimeMillis();
                                writeTransport();
                            }
                            if (!frame.isNull("data")) {
                                String changed = frame.getString("path");
                                if (changed.equals("/")) poll();
                                else {
                                    String[] parts = changed.split("/");
                                    if (parts.length > 1) enqueue(parts[1]);
                                }
                            }
                        }
                        event = "";
                        data.setLength(0);
                    } else if (line.startsWith("event:")) event = line.substring(6).trim();
                    else if (line.startsWith("data:")) {
                        if (data.length() > 0) data.append('\n');
                        data.append(line.substring(5).trim());
                        require(data.length() <= MAX_RESPONSE, "STREAM_FRAME_SIZE");
                    }
                }
            }
        } finally { disconnect(connection); }
    }

    private HttpsURLConnection openStream(String target) throws Exception {
        for (int redirect = 0; redirect < 4; redirect++) {
            synchronized (this) { streamAttempts++; writeTransport(); }
            HttpsURLConnection connection = open(target, "GET");
            connection.setRequestProperty("Accept", "text/event-stream");
            connection.setRequestProperty("Accept-Encoding", "identity");
            connection.setReadTimeout(15000);
            try {
                int code = connection.getResponseCode();
                synchronized (this) {
                    lastHttpStatus = code;
                    if (code == 200) streamConnections++;
                    writeTransport();
                }
                rejectAuthentication(code, "GET", "stream");
                if (code != 307) return connection;
                String location = connection.getHeaderField("Location");
                require(location != null, "STREAM_REDIRECT");
                URL next = new URL(new URL(target), location);
                require(firebaseHost(next.getHost()), "STREAM_REDIRECT_HOST");
                target = next.toExternalForm();
            } catch (Exception error) {
                disconnect(connection);
                throw error;
            }
            disconnect(connection);
        }
        throw new ProtocolFailure("STREAM_REDIRECT_LIMIT");
    }

    private static String boundedLine(BufferedReader reader) throws IOException {
        StringBuilder value = new StringBuilder();
        int next;
        while ((next = reader.read()) != -1) {
            if (next == '\n') break;
            if (next != '\r') value.append((char) next);
            if (value.length() > MAX_RESPONSE) throw new IOException("Frame too large");
        }
        return next == -1 && value.length() == 0 ? null : value.toString();
    }

    private void execute(String id) throws Exception {
        if (!active() || terminalSeen(id)) return;
        Response incoming = request(databaseUrl(path("inboxes") + "/" + id), "GET", null, null, false);
        require(incoming.code == 200 && !incoming.body.trim().equals("null"), "JOB_MISSING");
        JSONObject job = new JSONObject(incoming.body);
        validate(job, id, incoming.serverNow());
        String endpoint = databaseUrl(path("executions") + "/" + id);
        JSONObject lease = null;
        for (int retry = 0; retry < 3 && active(); retry++) {
            Response current = request(endpoint, "GET", null, null, true);
            require(current.code == 200 && current.etag != null, "LEASE_READ_FAILED");
            long now = current.serverNow();
            JSONObject previous = current.body.trim().equals("null") ? null : new JSONObject(current.body);
            int attempt = 1;
            if (previous != null) {
                require(matches(previous, job), "EXECUTION_CONFLICT");
                String state = previous.getString("state");
                if (state.equals("completed") || state.equals("failed")) { rememberTerminal(id); return; }
                require(state.equals("leased"), "EXECUTION_STATE");
                if (previous.getLong("lease_until_ms") > now) return;
                attempt = Math.addExact(previous.getInt("attempt"), 1);
            }
            require(now < job.getLong("expires_at_ms"), "JOB_EXPIRED");
            long until = Math.min(Math.min(now + LEASE_MS, config.expires), job.getLong("expires_at_ms"));
            require(until - now >= 5000, "LEASE_WINDOW_INSUFFICIENT");
            lease = identity(job).put("state", "leased").put("lease_id", randomId())
                    .put("lease_until_ms", until)
                    .put("attempt", attempt).put("started_at_ms", serverTimestamp());
            Response written = request(endpoint, "PUT", lease.toString(), current.etag, false);
            if (written.code == 200) {
                JSONObject resolved = new JSONObject(written.body);
                require(matches(resolved, job) && "leased".equals(resolved.getString("state"))
                        && lease.getString("lease_id").equals(resolved.getString("lease_id"))
                        && integer(resolved, "attempt") == attempt && integer(resolved, "lease_until_ms") == until,
                        "LEASE_RESPONSE_IDENTITY");
                long resolvedStart = integer(resolved, "started_at_ms");
                require(resolvedStart >= job.getLong("created_at_ms") && resolvedStart < until
                        && resolvedStart <= written.serverNow() + 2000, "LEASE_RESPONSE_START");
                lease = resolved;
                break;
            }
            require(written.code == 412, "LEASE_WRITE_FAILED");
            lease = null;
        }
        if (lease == null || !active()) return;
        long started = SystemClock.elapsedRealtime();
        JSONObject terminal = new JSONObject(lease.toString());
        try {
            JSONObject result = workerIdentity();
            String operation = job.getString("operation");
            if (operation.equals("echo_sha256"))
                result.put("challenge_sha256", hash(decodeChallenge(job.getString("challenge_base64url"))));
            else {
                String token = integrity(job, lease.getLong("lease_until_ms"));
                require(token.length() <= MAX_TOKEN && !token.isEmpty(), "INTEGRITY_TOKEN_SIZE");
                result.put("token", token).put("token_sha256", hash(token.getBytes(StandardCharsets.UTF_8)))
                        .put("token_length", token.length())
                        .put("nonce_base64url", job.getString("challenge_base64url"));
            }
            result.put("execution_elapsed_ms", SystemClock.elapsedRealtime() - started)
                    .put("completed_at_ms", serverTimestamp());
            terminal.put("state", "completed").put("result", result);
        } catch (Exception error) {
            if (isAuthenticationFailure(error)) throw error;
            if (!active()) return;
            JSONObject failure = new JSONObject().put("code", error instanceof ProtocolFailure
                    ? ((ProtocolFailure) error).code : "EXECUTION_FAILED")
                    .put("message", safeClass(error));
            if (error instanceof IntegrityServiceException)
                failure.put("error_code", ((IntegrityServiceException) error).getErrorCode());
            terminal.put("state", "failed").put("error", failure);
        }
        finish(endpoint, job, lease, terminal);
    }

    private void finish(String endpoint, JSONObject job, JSONObject lease, JSONObject terminal) throws Exception {
        for (int retry = 0; retry < 3 && active(); retry++) {
            Response current = request(endpoint, "GET", null, null, true);
            require(current.code == 200 && current.etag != null, "FINISH_READ_FAILED");
            require(current.serverNow() + 2000 < lease.getLong("lease_until_ms"), "LEASE_WINDOW_INSUFFICIENT");
            JSONObject existing = new JSONObject(current.body);
            if (matches(existing, job) && ("completed".equals(existing.optString("state"))
                    || "failed".equals(existing.optString("state")))) {
                rememberTerminal(job.getString("job_id"));
                return;
            }
            if (!matches(existing, job) || !"leased".equals(existing.optString("state"))
                    || !lease.getString("lease_id").equals(existing.optString("lease_id"))) return;
            Response written = request(endpoint, "PUT", terminal.toString(), current.etag, false);
            if (written.code == 200) {
                rememberTerminal(job.getString("job_id"));
                status.accept("Job " + terminal.getString("state") + ". Result belongs to this worker.");
                return;
            }
            require(written.code == 412, "FINISH_WRITE_FAILED");
        }
    }

    private String integrity(JSONObject job, long leaseUntil) throws Exception {
        ServerClock clock = serverClock;
        require(clock != null, "SERVER_DATE_MISSING");
        long remaining = Math.min(job.getLong("expires_at_ms"), leaseUntil) - clock.now() - 2000;
        require(remaining > 0, "LEASE_WINDOW_INSUFFICIENT");
        long deadline = SystemClock.elapsedRealtime() + Math.min(60000, remaining);
        CountDownLatch done = new CountDownLatch(1);
        Task<IntegrityTokenResponse> task = IntegrityManagerFactory.create(context).requestIntegrityToken(
                IntegrityTokenRequest.builder().setNonce(job.getString("challenge_base64url"))
                        .setCloudProjectNumber(job.getLong("cloud_project_number")).build());
        task.addOnCompleteListener(Runnable::run, completed -> done.countDown());
        while (active() && SystemClock.elapsedRealtime() < deadline) {
            if (done.await(250, TimeUnit.MILLISECONDS)) {
                if (task.isSuccessful()) return task.getResult().token();
                Exception error = task.getException();
                if (error != null) throw error;
                throw new ProtocolFailure("INTEGRITY_FAILED");
            }
        }
        throw new ProtocolFailure("INTEGRITY_TIMEOUT");
    }

    private JSONObject workerIdentity() throws Exception {
        PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(),
                PackageManager.GET_SIGNING_CERTIFICATES);
        require(info.signingInfo != null && info.signingInfo.getApkContentsSigners().length == 1,
                "WORKER_SIGNER_COUNT");
        return new JSONObject().put("worker_package", context.getPackageName())
                .put("worker_version_code", info.getLongVersionCode())
                .put("worker_apk_cert_sha256", hash(info.signingInfo.getApkContentsSigners()[0].toByteArray()));
    }

    private void validate(JSONObject job, String id, long now) throws Exception {
        require(integer(job, "schema_version") == 1 && id.equals(job.getString("job_id"))
                && config.sid.equals(job.getString("session_id")) && config.uid.equals(job.getString("worker_uid")), "JOB_IDENTITY");
        String operation = job.getString("operation");
        require(operation.equals("echo_sha256") || operation.equals("play_integrity"), "JOB_OPERATION");
        decodeChallenge(job.getString("challenge_base64url"));
        long project = integer(job, "cloud_project_number");
        require(project == config.project && project > 0 && project <= 9007199254740991L, "JOB_PROJECT");
        long created = integer(job, "created_at_ms"), expires = integer(job, "expires_at_ms");
        require(created > 0 && created <= now + 30000 && expires > now && expires > created
                && expires - created <= 300000 && expires <= config.expires, "JOB_TTL");
        String canonical = "v1\n" + config.sid + "\n" + config.uid + "\n" + id + "\n" + operation
                + "\n" + job.getString("challenge_base64url") + "\n" + project + "\n" + created + "\n" + expires;
        require(hash(canonical.getBytes(StandardCharsets.UTF_8)).equals(job.getString("request_sha256")), "JOB_HASH");
    }

    private static JSONObject identity(JSONObject job) throws Exception {
        JSONObject result = new JSONObject();
        for (String key : new String[] {"job_id", "session_id", "worker_uid", "operation", "request_sha256"})
            result.put(key, job.getString(key));
        return result;
    }

    private static boolean matches(JSONObject value, JSONObject job) throws Exception {
        for (String key : new String[] {"job_id", "session_id", "worker_uid", "operation", "request_sha256"})
            if (!job.getString(key).equals(value.optString(key))) return false;
        return true;
    }

    private static byte[] decodeChallenge(String value) throws Exception {
        require(value.matches("[A-Za-z0-9_-]{43}"), "CHALLENGE_FORMAT");
        byte[] bytes = Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        require(bytes.length == 32 && Base64.encodeToString(bytes, Base64.URL_SAFE | Base64.NO_WRAP
                | Base64.NO_PADDING).equals(value), "CHALLENGE_FORMAT");
        return bytes;
    }

    private HttpsURLConnection open(String target, String method) throws Exception {
        require(!closed, "STOPPED");
        URL url = new URL(target);
        require(url.getProtocol().equals("https") && url.getUserInfo() == null && url.getRef() == null
                && (url.getPort() == -1 || url.getPort() == 443), "HTTPS_REQUIRED");
        String host = url.getHost();
        require(host.equals("identitytoolkit.googleapis.com") || firebaseHost(host), "HOST_REJECTED");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        connection.setRequestMethod(method);
        connection.setUseCaches(false);
        connections.add(connection);
        if (closed) { disconnect(connection); throw new ProtocolFailure("STOPPED"); }
        return connection;
    }

    private Response request(String target, String method, String body, String etag, boolean wantEtag) throws Exception {
        HttpsURLConnection connection = open(target, method);
        try {
            if (wantEtag) connection.setRequestProperty("X-Firebase-ETag", "true");
            if (etag != null) connection.setRequestProperty("If-Match", etag);
            if (body != null) {
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                require(bytes.length <= MAX_RESPONSE, "REQUEST_SIZE");
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                connection.setFixedLengthStreamingMode(bytes.length);
                try (java.io.OutputStream output = connection.getOutputStream()) { output.write(bytes); }
            }
            int code = connection.getResponseCode();
            long receivedAt = SystemClock.elapsedRealtime();
            long responseDate = connection.getHeaderFieldDate("Date", 0);
            synchronized (this) { lastHttpStatus = code; writeTransport(); }
            String scope = requestScope(target);
            ServerClock responseClock = responseDate > 0 ? new ServerClock(responseDate, receivedAt) : null;
            if (code == 200 && !scope.equals("identity") && responseClock != null) serverClock = responseClock;
            rejectAuthentication(code, method, scope);
            if (code >= 400) writeFailure("HTTP_" + code, code, method, scope);
            String response;
            InputStream input = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
            if (input == null) response = "";
            else try (InputStream stream = input) { response = readBounded(stream); }
            return new Response(code, response, connection.getHeaderField("ETag"), responseClock);
        } finally { disconnect(connection); }
    }

    private static String readBounded(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            require(output.size() + count <= MAX_RESPONSE, "RESPONSE_SIZE");
            output.write(buffer, 0, count);
        }
        return output.toString(StandardCharsets.UTF_8.name());
    }

    private void disconnect(HttpsURLConnection connection) {
        connections.remove(connection);
        connection.disconnect();
    }

    private void pause(long millis) {
        try { if (!closed) Thread.sleep(millis); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); }
    }

    private void rejectAuthentication(int code, String method, String scope) throws Exception {
        if (code != 401 && code != 403) return;
        if (scope.equals("execution")) {
            HttpsURLConnection check = open(databaseUrl(path("inboxes")), "GET");
            try {
                int sessionCode = check.getResponseCode();
                if (sessionCode == 200) {
                    writeFailure("JOB_AUTHORIZATION_REJECTED", code, method, scope);
                    throw new ProtocolFailure("JOB_AUTHORIZATION_REJECTED");
                }
                if (sessionCode != 401 && sessionCode != 403) {
                    writeFailure("AUTH_CHECK_UNAVAILABLE", sessionCode, "GET", "inbox");
                    throw new IOException("Authorization check unavailable");
                }
                writeFailure("AUTHORIZATION_REJECTED", sessionCode, "GET", "inbox");
            } finally { disconnect(check); }
        } else writeFailure("AUTHORIZATION_REJECTED", code, method, scope);
        throw new ProtocolFailure("AUTHORIZATION_REJECTED");
    }

    private static String requestScope(String target) throws Exception {
        URL url = new URL(target);
        if (url.getHost().equals("identitytoolkit.googleapis.com")) return "identity";
        return url.getPath().startsWith("/relay/v1/executions/") ? "execution" : "inbox";
    }

    private synchronized boolean terminalSeen(String id) { return terminalIds.contains(id); }

    private synchronized void rememberTerminal(String id) {
        if (terminalIds.add(id) && terminalIds.size() > 4096) {
            Iterator<String> oldest = terminalIds.iterator();
            oldest.next();
            oldest.remove();
        }
    }

    private synchronized void writeFailure(String code, int httpStatus, String method, String scope) {
        AtomicFile file = new AtomicFile(new File(context.getFilesDir(), "worker-failure.json"));
        FileOutputStream output = null;
        try {
            JSONObject diagnostic = new JSONObject().put("code", code).put("status", httpStatus)
                    .put("method", method).put("scope", scope)
                    .put("timestamp", System.currentTimeMillis());
            output = file.startWrite();
            output.write(diagnostic.toString().getBytes(StandardCharsets.UTF_8));
            file.finishWrite(output);
        } catch (Exception ignored) {
            if (output != null) file.failWrite(output);
        }
    }

    private synchronized void transportFailure(Throwable error) {
        if (error instanceof ProtocolFailure) lastTransportError = "PROTOCOL_FAILURE";
        else if (error instanceof java.net.SocketTimeoutException) lastTransportError = "SOCKET_TIMEOUT";
        else if (error instanceof IOException) lastTransportError = "IO_FAILURE";
        else if (error instanceof InterruptedException) lastTransportError = "INTERRUPTED";
        else lastTransportError = "OTHER_FAILURE";
        writeTransport();
    }

    private synchronized void writeTransport() {
        AtomicFile file = new AtomicFile(new File(context.getFilesDir(), "worker-transport.json"));
        FileOutputStream output = null;
        try {
            JSONObject diagnostic = new JSONObject().put("stream_attempts", streamAttempts)
                    .put("stream_connections", streamConnections).put("event_count", eventCount)
                    .put("poll_count", pollCount).put("last_event_at_ms", lastEventAtMs)
                    .put("last_poll_at_ms", lastPollAtMs).put("last_http_status", lastHttpStatus)
                    .put("last_error_code", lastTransportError).put("started_at_ms", transportStartedAtMs)
                    .put("updated_at_ms", System.currentTimeMillis());
            byte[] bytes = diagnostic.toString().getBytes(StandardCharsets.UTF_8);
            if (bytes.length > 4096) return;
            output = file.startWrite();
            output.write(bytes);
            file.finishWrite(output);
        } catch (Exception ignored) {
            if (output != null) file.failWrite(output);
        }
    }

    private static boolean isAuthenticationFailure(Exception error) {
        if (!(error instanceof ProtocolFailure)) return false;
        String code = ((ProtocolFailure) error).code;
        return code.equals("AUTHORIZATION_REJECTED") || code.equals("STREAM_AUTH_REJECTED");
    }

    private void stopForAuthentication() {
        status.accept("Stopped: authorization rejected");
        close();
    }

    @Override public void close() {
        closed = true;
        idToken = null;
        if (config != null) config.customToken = null;
        for (HttpsURLConnection connection : connections) connection.disconnect();
        connections.clear();
        transport.shutdownNow();
        execution.shutdownNow();
    }

    private static String randomId() { return UUID.randomUUID().toString().replace("-", ""); }
    private static JSONObject serverTimestamp() throws Exception { return new JSONObject().put(".sv", "timestamp"); }
    private static boolean firebaseHost(String host) {
        return host.matches("[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:firebaseio\\.com|firebasedatabase\\.app)");
    }
    private static long integer(JSONObject value, String key) throws Exception {
        Object number = value.get(key);
        require(number instanceof Integer || number instanceof Long, "INTEGER_REQUIRED");
        return ((Number) number).longValue();
    }
    private static String safeClass(Throwable error) { return error.getClass().getSimpleName().replaceAll("[^A-Za-z0-9_]", ""); }
    private static String hash(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder value = new StringBuilder();
        for (byte b : digest) value.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return value.toString();
    }
    private static void require(boolean condition, String code) throws ProtocolFailure {
        if (!condition) throw new ProtocolFailure(code);
    }
    private static final class ProtocolFailure extends Exception {
        final String code;
        ProtocolFailure(String code) { super(code); this.code = code; }
    }
    private static final class Response {
        final int code;
        final String body, etag;
        final ServerClock clock;
        Response(int code, String body, String etag, ServerClock clock) {
            this.code = code; this.body = body; this.etag = etag; this.clock = clock;
        }
        long serverNow() throws ProtocolFailure {
            require(clock != null, "SERVER_DATE_MISSING");
            return clock.now();
        }
    }
    private static final class ServerClock {
        final long epochMs, elapsedMs;
        ServerClock(long epochMs, long elapsedMs) { this.epochMs = epochMs; this.elapsedMs = elapsedMs; }
        long now() { return epochMs + Math.max(0, SystemClock.elapsedRealtime() - elapsedMs); }
    }
    private static final class Config {
        String database, apiKey, customToken, sid, uid;
        long expires, project;
        static Config load(File file) throws Exception {
            require(file.isFile() && file.length() > 0 && file.length() <= MAX_RESPONSE, "CONFIG_SIZE");
            JSONObject json = new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
            require(integer(json, "schema_version") == 1, "CONFIG_SCHEMA");
            Config config = new Config();
            config.database = json.getString("database_url");
            URL url = new URL(config.database);
            require(url.getProtocol().equals("https") && url.getUserInfo() == null && url.getQuery() == null
                    && url.getRef() == null && (url.getPath().isEmpty() || url.getPath().equals("/"))
                    && (url.getPort() == -1 || url.getPort() == 443)
                    && firebaseHost(url.getHost()), "CONFIG_DATABASE");
            config.database = "https://" + url.getHost();
            config.apiKey = json.getString("api_key");
            require(config.apiKey.matches("[A-Za-z0-9_-]{20,256}"), "CONFIG_API_KEY");
            config.customToken = json.getString("custom_token");
            require(config.customToken.length() > 0 && config.customToken.length() <= MAX_TOKEN, "CONFIG_TOKEN");
            config.sid = json.getString("session_id");
            config.uid = json.getString("worker_uid");
            require(config.sid.matches("[a-f0-9]{32}") && config.uid.matches("worker_[a-f0-9]{24}"), "CONFIG_ID");
            config.expires = integer(json, "session_expires_at_ms");
            long remaining = config.expires - System.currentTimeMillis();
            require(remaining > 0 && remaining <= 1800000, "CONFIG_TTL");
            config.project = integer(json, "cloud_project_number");
            require(config.project > 0 && config.project <= 9007199254740991L, "CONFIG_PROJECT");
            return config;
        }
    }
}
