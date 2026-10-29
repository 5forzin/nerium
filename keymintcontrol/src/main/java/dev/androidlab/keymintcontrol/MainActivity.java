package dev.androidlab.keymintcontrol;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import android.util.Base64;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.x500.X500Principal;

public final class MainActivity extends Activity {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PUBLIC_PROVIDER = "AndroidOpenSSL";
    private static final X500Principal SUBJECT = new X500Principal("CN=AndroidLab KeyMint Control");
    private static final byte[] PAYLOAD = "AndroidLab public KeyMint control payload v1".getBytes(StandardCharsets.UTF_8);
    private static final PSSParameterSpec PSS = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<String> ownedAliases = new ArrayList<>();
    private Button button;
    private TextView status;
    private KeyStore store;
    private String prefix;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        status = new TextView(this);
        status.setText("Creates temporary Android Keystore keys, checks operations, then deletes them. No network access.");
        layout.addView(status);
        button = new Button(this);
        button.setAllCaps(false);
        button.setText("Run checks");
        button.setOnClickListener(view -> {
            button.setEnabled(false);
            status.setText("Running checks…");
            worker.execute(this::runChecks);
        });
        layout.addView(button);
        setContentView(layout);
    }

    private interface Check { void run(JSONObject result) throws Exception; }
    private interface Operation { void run() throws Exception; }
    private static final class CheckFailure extends IllegalStateException {
        final String code;
        CheckFailure(String code) { super(code); this.code = code; }
    }

    private void runChecks() {
        JSONObject report = new JSONObject();
        JSONObject controls = new JSONObject();
        String runId = UUID.randomUUID().toString().replace("-", "");
        prefix = "androidlab_keymint_control_" + runId + "_";
        ownedAliases.clear();
        boolean passed = false;
        try {
            report.put("schema_version", 1).put("run_id", runId).put("sdk_int", Build.VERSION.SDK_INT)
                    .put("status", "failed").put("controls", controls).put("started_at_ms", System.currentTimeMillis());
            store = KeyStore.getInstance(KEYSTORE);
            store.load(null);
            boolean rsa = control(controls, "rsa_pss_sha256", this::rsa);
            boolean ec = control(controls, "ec_p256_sha256", this::ec);
            boolean aes = control(controls, "aes_256_gcm", this::aes);
            boolean hmac = control(controls, "hmac_sha256", this::hmac);
            passed = rsa && ec && aes && hmac;
        } catch (Exception error) {
            put(report, "error_class", safeClass(error));
        } finally {
            JSONObject cleanup = cleanup();
            put(report, "cleanup", cleanup);
            passed = passed && cleanup.optBoolean("all_removed", false);
            put(report, "status", passed ? "passed" : "failed");
            put(report, "completed_at_ms", System.currentTimeMillis());
            final String outcome = passed ? "Checks passed." : "Checks failed. See result.json.";
            try {
                writeReport(report);
                runOnUiThread(() -> { status.setText(outcome); button.setEnabled(true); });
            } catch (Exception error) {
                runOnUiThread(() -> { status.setText("Report could not be saved."); button.setEnabled(true); });
            }
        }
    }

    private boolean control(JSONObject controls, String name, Check check) throws Exception {
        JSONObject result = new JSONObject().put("status", "failed");
        controls.put(name, result);
        try {
            check.run(result);
            result.put("status", "passed");
            return true;
        } catch (Exception error) {
            result.put("error_class", safeClass(error));
            if (error instanceof CheckFailure) result.put("check_code", ((CheckFailure) error).code);
            return false;
        }
    }

    private String alias(String suffix) {
        String value = prefix + suffix;
        ownedAliases.add(value);
        return value;
    }

    private KeyGenParameterSpec.Builder spec(String alias, int purposes) {
        return new KeyGenParameterSpec.Builder(alias, purposes).setUserAuthenticationRequired(false);
    }

    private void rsa(JSONObject result) throws Exception {
        String alias = alias("rsa");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE);
        generator.initialize(spec(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                .setDigests(KeyProperties.DIGEST_SHA256).setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setCertificateSubject(SUBJECT).setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(new Date(1704067200000L)).setCertificateNotAfter(new Date(2208988800000L)).build());
        KeyPair pair = generator.generateKeyPair();
        require(pair.getPrivate().getEncoded() == null, "PRIVATE_KEY_EXPORTABLE");
        JSONObject keyInfo = info(pair.getPrivate());
        require(keyInfo.getInt("key_size") == 2048, "RSA_KEYINFO_SIZE");
        result.put("private_encoding_null", true).put("key_info", keyInfo);
        Signature signer = Signature.getInstance("SHA256withRSA/PSS");
        signer.initSign(pair.getPrivate());
        signer.update(PAYLOAD);
        byte[] signature = signer.sign();
        result.put("signer_provider", signer.getProvider().getName());
        PublicKey publicKey = KeyFactory.getInstance("RSA", PUBLIC_PROVIDER)
                .generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
        RSAPublicKey rsa = (RSAPublicKey) publicKey;
        require(rsa.getModulus().bitLength() == 2048 && rsa.getPublicExponent().equals(BigInteger.valueOf(65537)), "RSA_PARAMETERS");
        Signature verifier = Signature.getInstance("SHA256withRSA/PSS", PUBLIC_PROVIDER);
        verifier.setParameter(PSS);
        verifier.initVerify(publicKey);
        verifier.update(PAYLOAD);
        require(verifier.verify(signature), "RSA_VALID_SIGNATURE_REJECTED");
        result.put("valid_signature_verified", true).put("public_verifier_provider", verifier.getProvider().getName())
                .put("digest", "SHA-256").put("mgf1_digest", "SHA-256").put("salt_length", 32);
        byte[] altered = signature.clone(); altered[altered.length - 1] ^= 1;
        verifier.initVerify(publicKey); verifier.setParameter(PSS); verifier.update(PAYLOAD);
        boolean rejected;
        try { rejected = !verifier.verify(altered); }
        catch (SignatureException expected) { rejected = true; }
        require(rejected, "RSA_TAMPER_ACCEPTED");
        result.put("tampered_signature_rejected", true);
        X509Certificate certificate = (X509Certificate) store.getCertificate(alias);
        byte[] der = certificate.getEncoded();
        require(der.length <= 16384, "CERTIFICATE_SIZE");
        X509Certificate decoded = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        decoded.checkValidity();
        require(SUBJECT.equals(decoded.getSubjectX500Principal()), "CERTIFICATE_SUBJECT");
        require(Arrays.equals(publicKey.getEncoded(), decoded.getPublicKey().getEncoded()), "CERTIFICATE_PUBLIC_KEY");
        boolean selfVerified = false;
        String selfError = "none";
        try { decoded.verify(publicKey); selfVerified = true; }
        catch (Exception observation) { selfError = safeClass(observation); }
        result.put("certificate_decoded", true).put("certificate_subject_matches", true)
                .put("certificate_spki_matches", true).put("certificate_self_signature_verified", selfVerified)
                .put("certificate_self_signature_error_class", selfError)
                .put("certificate_self_signature_classification", "observation")
                .put("public_evidence", new JSONObject().put("certificate_der_base64", base64(der))
                        .put("spki_base64", base64(publicKey.getEncoded())).put("payload_base64", base64(PAYLOAD))
                        .put("signature_base64", base64(signature)));
        store.deleteEntry(alias);
        result.put("deleted_key_rejected", rejectedDeleted(() -> {
            Signature attempt = Signature.getInstance("SHA256withRSA/PSS");
            attempt.initSign(pair.getPrivate()); attempt.update(PAYLOAD); attempt.sign();
        }));
    }

    private void ec(JSONObject result) throws Exception {
        String alias = alias("ec");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE);
        generator.initialize(spec(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256).build());
        KeyPair pair = generator.generateKeyPair();
        require(pair.getPrivate().getEncoded() == null, "PRIVATE_KEY_EXPORTABLE");
        require(((ECPublicKey) pair.getPublic()).getParams().getCurve().getField().getFieldSize() == 256, "EC_PARAMETERS");
        JSONObject keyInfo = info(pair.getPrivate());
        require(keyInfo.getInt("key_size") == 256, "EC_KEYINFO_SIZE");
        result.put("private_encoding_null", true).put("key_info", keyInfo);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate()); signer.update(PAYLOAD); byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA", PUBLIC_PROVIDER);
        verifier.initVerify(pair.getPublic()); verifier.update(PAYLOAD);
        require(verifier.verify(signature), "EC_SIGNATURE_INVALID");
        byte[] changed = PAYLOAD.clone(); changed[0] ^= 1;
        verifier.initVerify(pair.getPublic()); verifier.update(changed);
        require(!verifier.verify(signature), "EC_TAMPER_ACCEPTED");
        result.put("valid_signature_verified", true).put("changed_payload_rejected", true);
        store.deleteEntry(alias);
        result.put("deleted_key_rejected", rejectedDeleted(() -> {
            Signature attempt = Signature.getInstance("SHA256withECDSA");
            attempt.initSign(pair.getPrivate()); attempt.update(PAYLOAD); attempt.sign();
        }));
    }

    private void aes(JSONObject result) throws Exception {
        String alias = alias("aes");
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(spec(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
        SecretKey key = generator.generateKey();
        require(key.getEncoded() == null, "SECRET_KEY_EXPORTABLE");
        JSONObject keyInfo = info(key);
        require(keyInfo.getInt("key_size") == 256, "AES_KEYINFO_SIZE");
        result.put("private_encoding_null", true).put("key_info", keyInfo);
        Cipher encryptor = Cipher.getInstance("AES/GCM/NoPadding");
        encryptor.init(Cipher.ENCRYPT_MODE, key); byte[] ciphertext = encryptor.doFinal(PAYLOAD);
        GCMParameterSpec parameters = new GCMParameterSpec(128, encryptor.getIV());
        Cipher decryptor = Cipher.getInstance("AES/GCM/NoPadding");
        decryptor.init(Cipher.DECRYPT_MODE, key, parameters);
        require(Arrays.equals(PAYLOAD, decryptor.doFinal(ciphertext)), "AES_ROUNDTRIP");
        byte[] altered = ciphertext.clone(); altered[altered.length - 1] ^= 1;
        decryptor.init(Cipher.DECRYPT_MODE, key, parameters);
        boolean rejected = false;
        try { decryptor.doFinal(altered); } catch (AEADBadTagException expected) { rejected = true; }
        require(rejected, "AES_TAMPER_ACCEPTED");
        result.put("roundtrip_verified", true).put("altered_ciphertext_rejected", true);
        store.deleteEntry(alias);
        result.put("deleted_key_rejected", rejectedDeleted(() -> {
            Cipher attempt = Cipher.getInstance("AES/GCM/NoPadding");
            attempt.init(Cipher.ENCRYPT_MODE, key); attempt.doFinal(PAYLOAD);
        }));
    }

    private void hmac(JSONObject result) throws Exception {
        String alias = alias("hmac");
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE);
        generator.init(spec(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY).setKeySize(256).setDigests(KeyProperties.DIGEST_SHA256).build());
        SecretKey key = generator.generateKey();
        require(key.getEncoded() == null, "SECRET_KEY_EXPORTABLE");
        JSONObject keyInfo = info(key);
        require(keyInfo.getInt("key_size") == 256, "HMAC_KEYINFO_SIZE");
        result.put("private_encoding_null", true).put("key_info", keyInfo);
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(key);
        byte[] first = mac.doFinal(PAYLOAD); byte[] second = mac.doFinal(PAYLOAD);
        byte[] changed = PAYLOAD.clone(); changed[0] ^= 1;
        byte[] third = mac.doFinal(changed);
        require(first.length == 32 && MessageDigest.isEqual(first, second), "HMAC_SAME_INPUT");
        require(!MessageDigest.isEqual(first, third), "HMAC_CHANGED_INPUT");
        result.put("same_input_matches", true).put("changed_input_differs", true);
        store.deleteEntry(alias);
        result.put("deleted_key_rejected", rejectedDeleted(() -> {
            Mac attempt = Mac.getInstance("HmacSHA256"); attempt.init(key); attempt.doFinal(PAYLOAD);
        }));
    }

    @SuppressWarnings("deprecation")
    private JSONObject info(Key key) throws Exception {
        KeyInfo info = key instanceof PrivateKey
                ? KeyFactory.getInstance(key.getAlgorithm(), KEYSTORE).getKeySpec(key, KeyInfo.class)
                : (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE).getKeySpec((SecretKey) key, KeyInfo.class);
        JSONObject result = new JSONObject().put("inside_secure_hardware", info.isInsideSecureHardware())
                .put("key_size", info.getKeySize()).put("user_authentication_required", info.isUserAuthenticationRequired());
        require(!info.isUserAuthenticationRequired(), "UNEXPECTED_AUTHENTICATION_REQUIRED");
        if (Build.VERSION.SDK_INT >= 31) {
            int level = info.getSecurityLevel();
            result.put("security_level", level);
            boolean known = level == KeyProperties.SECURITY_LEVEL_SOFTWARE || level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                    || level == KeyProperties.SECURITY_LEVEL_STRONGBOX;
            require(known, "UNKNOWN_SECURITY_LEVEL");
            require(info.isInsideSecureHardware() == (level != KeyProperties.SECURITY_LEVEL_SOFTWARE), "SECURITY_LEVEL_INCONSISTENT");
            result.put("security_level_consistent", true);
        } else { result.put("security_level", "not_available_before_api_31"); }
        return result;
    }

    private boolean rejectedDeleted(Operation operation) throws Exception {
        try { operation.run(); }
        catch (InvalidKeyException expected) { return true; }
        throw new IllegalStateException("DELETED_KEY_ACCEPTED_OR_UNEXPECTED_ERROR");
    }

    private JSONObject cleanup() {
        int removed = 0, remaining = 0, errors = 0;
        for (String alias : ownedAliases) {
            try {
                if (store == null) { errors++; continue; }
                store.deleteEntry(alias);
                if (store.containsAlias(alias)) remaining++; else removed++;
            } catch (Exception error) { errors++; }
        }
        JSONObject result = new JSONObject();
        put(result, "owned_count", ownedAliases.size()); put(result, "removed_count", removed);
        put(result, "remaining_count", remaining); put(result, "error_count", errors);
        put(result, "all_removed", remaining == 0 && errors == 0 && removed == ownedAliases.size());
        return result;
    }

    private void writeReport(JSONObject report) throws Exception {
        AtomicFile file = new AtomicFile(new File(getFilesDir(), "result.json"));
        FileOutputStream output = null;
        try {
            output = file.startWrite(); output.write(report.toString(2).getBytes(StandardCharsets.UTF_8));
            file.finishWrite(output);
        } catch (Exception error) { if (output != null) file.failWrite(output); throw error; }
    }
    private static String base64(byte[] value) { return Base64.encodeToString(value, Base64.NO_WRAP); }
    private static String safeClass(Exception error) { return error.getClass().getSimpleName(); }
    private static void require(boolean condition, String code) { if (!condition) throw new CheckFailure(code); }
    private static void put(JSONObject object, String key, Object value) {
        try { object.put(key, value); } catch (Exception ignored) { }
    }
}
