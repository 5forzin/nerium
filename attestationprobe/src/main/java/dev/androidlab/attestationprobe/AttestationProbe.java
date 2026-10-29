package dev.androidlab.attestationprobe;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;

final class AttestationProbe {
    JSONObject collect(Context context, byte[] challenge) throws Exception {
        JSONObject result = new JSONObject();
        result.put("schema_version", 1);
        result.put("captured_at_ms", System.currentTimeMillis());
        result.put("api", Build.VERSION.SDK_INT);
        result.put("challenge_source", challenge == null ? "device" : "external");
        result.put("hardware_attestation_feature", context.getPackageManager().hasSystemFeature("android.hardware.hardware_keystore"));
        result.put("strongbox_feature", context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE));
        result.put("default_keystore", measure(false, challenge));
        result.put("strongbox", measure(true, challenge));
        result.put("interpretation", "Valid signatures and nonce binding do not establish manufacturer trust or hardware-backed storage.");
        return result;
    }

    @SuppressWarnings("deprecation")
    private JSONObject measure(boolean strongBox, byte[] suppliedChallenge) throws Exception {
        String alias = "device-lab-attestation-" + (strongBox ? "strongbox" : "default");
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        store.deleteEntry(alias);
        JSONObject result = new JSONObject();
        try {
            byte[] challenge = suppliedChallenge == null ? new byte[32] : suppliedChallenge.clone();
            if (suppliedChallenge == null) new SecureRandom().nextBytes(challenge);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(strongBox).build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            generator.initialize(spec);
            long start = System.nanoTime();
            KeyPair pair = generator.generateKeyPair();
            result.put("generation_ms", (System.nanoTime() - start) / 1_000_000.0);
            KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(pair.getPrivate(), KeyInfo.class);
            result.put("keyinfo_inside_secure_hardware", info.isInsideSecureHardware());
            if (Build.VERSION.SDK_INT >= 31) result.put("keyinfo_security_level", info.getSecurityLevel());
            Certificate[] chain = store.getCertificateChain(alias);
            if (chain == null || chain.length == 0) throw new IllegalStateException("Keystore returned no certificates");
            JSONArray certificates = new JSONArray();
            boolean chainValidNow = true;
            for (int index = 0; index < chain.length; index++) {
                X509Certificate cert = (X509Certificate) chain[index];
                cert.verify(chain[Math.min(index + 1, chain.length - 1)].getPublicKey());
                JSONObject item = new JSONObject();
                item.put("subject", cert.getSubjectX500Principal().getName());
                item.put("issuer", cert.getIssuerX500Principal().getName());
                item.put("sha256", hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())));
                item.put("der_base64", Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
                try {
                    cert.checkValidity();
                    item.put("valid_now", true);
                } catch (java.security.cert.CertificateException validityError) {
                    chainValidNow = false;
                    item.put("valid_now", false);
                    item.put("validity_error", validityError.toString());
                }
                certificates.put(item);
            }
            result.put("certificates", certificates);
            result.put("chain_signatures_valid", true);
            result.put("chain_valid_now", chainValidNow);
            result.put("leaf_matches_generated_key", Arrays.equals(chain[0].getPublicKey().getEncoded(), pair.getPublic().getEncoded()));
            byte[] payload = "Device Lab independent key possession check".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(pair.getPrivate());
            signer.update(payload);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(chain[0].getPublicKey());
            verifier.update(payload);
            result.put("key_possession_verified", verifier.verify(signature));
            result.put("payload_base64", Base64.encodeToString(payload, Base64.NO_WRAP));
            result.put("signature_base64", Base64.encodeToString(signature, Base64.NO_WRAP));
            result.put("challenge_base64", Base64.encodeToString(challenge, Base64.NO_WRAP));
            result.put("attestation", describe((X509Certificate) chain[0], challenge));
            result.put("status", "complete");
        } catch (Exception error) {
            result.put("status", strongBox ? "unavailable" : "failed");
            result.put("error_type", error.getClass().getName());
            result.put("error", error.toString());
        } finally {
            store.deleteEntry(alias);
        }
        return result;
    }

    private JSONObject describe(X509Certificate cert, byte[] challenge) throws Exception {
        byte[] extension = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
        if (extension == null) throw new IllegalStateException("Attestation extension absent");
        List<Der> fields = Der.one(Der.one(extension).value).children();
        if (fields.size() != 8) throw new IllegalArgumentException("Unexpected attestation field count");
        JSONObject result = new JSONObject();
        result.put("attestation_version", fields.get(0).integer());
        result.put("attestation_security_level", fields.get(1).integer());
        result.put("keymaster_version", fields.get(2).integer());
        result.put("keymaster_security_level", fields.get(3).integer());
        result.put("challenge_matches", Arrays.equals(fields.get(4).value, challenge));
        for (int authorization = 6; authorization <= 7; authorization++) {
            for (Der tag : fields.get(authorization).children()) {
                if (tag.tagClass != 2 || tag.tag != 704) continue;
                List<Der> boot = Der.one(tag.value).children();
                JSONObject root = new JSONObject();
                root.put("authorization_list", authorization == 6 ? "software" : "hardware");
                root.put("verified_boot_key", hex(boot.get(0).value));
                root.put("device_locked", boot.get(1).value.length == 1 && boot.get(1).value[0] != 0);
                root.put("verified_boot_state", boot.get(2).integer());
                if (boot.size() > 3) root.put("verified_boot_hash", hex(boot.get(3).value));
                result.put("root_of_trust", root);
            }
        }
        return result;
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }
}
