package dev.androidlab.cngattestationcontrol;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

final class AttestationControl {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PUBLIC_PROVIDER = "AndroidOpenSSL";
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final String PROVISIONING_OID = "1.3.6.1.4.1.11129.2.1.30";
    private static final X500Principal SUBJECT = new X500Principal("CN=AndroidLab CNG Attestation Control");
    private static final X500Principal LAB_ROOT = new X500Principal("CN=AndroidLab Software Attestation Root");
    private static final PSSParameterSpec PSS = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    private static final class CheckFailure extends IllegalStateException {
        final String code;
        CheckFailure(String code) { super(code); this.code = code; }
    }

    @SuppressWarnings("deprecation")
    boolean collect(Context context, String supplied) throws Exception {
        long start = System.currentTimeMillis();
        JSONObject report = new JSONObject().put("schema_version", 1)
                .put("run_id", UUID.randomUUID().toString().replace("-", ""))
                .put("api", Build.VERSION.SDK_INT).put("started_at_ms", start)
                .put("challenge_source", supplied == null ? "missing" : "external")
                .put("challenge_base64", supplied == null ? JSONObject.NULL : supplied)
                .put("status", "failed");
        JSONObject sample = new JSONObject().put("status", "failed").put("started_at_ms", start)
                .put("challenge_base64", supplied == null ? JSONObject.NULL : supplied)
                .put("payload_scheme", "RSA_PSS_SHA256_SALT32")
                .put("manufacturer_trust", "not_established").put("google_attestation_verified", false)
                .put("android_tee_verified", false).put("lab_root_trusted", false);
        report.put("default_keystore", sample);
        KeyStore store = null;
        String alias = null;
        String stage = "external_challenge";
        boolean complete = false;
        try {
            require(supplied != null && supplied.length() == 44, "EXTERNAL_CHALLENGE_REQUIRED");
            byte[] challenge = Base64.decode(supplied, Base64.NO_WRAP);
            require(challenge.length == 32 && base64(challenge).equals(supplied), "CHALLENGE_FORMAT");
            if (Build.VERSION.SDK_INT < 31) throw new CheckFailure("KEYINFO_SECURITY_LEVEL_UNAVAILABLE");
            stage = "key_generation";
            store = KeyStore.getInstance(KEYSTORE);
            store.load(null);
            alias = "androidlab_cng_attestation_" + UUID.randomUUID().toString().replace("-", "");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                    .setUserAuthenticationRequired(false).setAttestationChallenge(challenge)
                    .setCertificateSubject(SUBJECT).setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(new Date(1704067200000L))
                    .setCertificateNotAfter(new Date(2208988800000L)).build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE);
            generator.initialize(spec);
            KeyPair pair = generator.generateKeyPair();
            require(pair.getPrivate().getEncoded() == null, "PRIVATE_KEY_EXPORTABLE");
            sample.put("private_encoding_null", true);
            KeyInfo info = KeyFactory.getInstance("RSA", KEYSTORE).getKeySpec(pair.getPrivate(), KeyInfo.class);
            sample.put("keyinfo_security_level", info.getSecurityLevel())
                    .put("keyinfo_inside_secure_hardware", info.isInsideSecureHardware())
                    .put("keyinfo_key_size", info.getKeySize()).put("keyinfo_purposes", info.getPurposes());
            require(info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_SOFTWARE && !info.isInsideSecureHardware(), "KEYINFO_NOT_SOFTWARE");
            require(info.getKeySize() == 2048 && info.getPurposes() == KeyProperties.PURPOSE_SIGN
                    && !info.isUserAuthenticationRequired(), "KEYINFO_PROFILE");
            require(Arrays.equals(info.getDigests(), new String[]{KeyProperties.DIGEST_SHA256})
                    && Arrays.equals(info.getSignaturePaddings(), new String[]{KeyProperties.SIGNATURE_PADDING_RSA_PSS}), "KEYINFO_AUTHORIZATIONS");

            stage = "certificate_chain";
            Certificate[] chain = store.getCertificateChain(alias);
            require(chain != null && chain.length == 2, "EXPECTED_TWO_CERTIFICATES");
            X509Certificate leaf = (X509Certificate) chain[0];
            X509Certificate root = (X509Certificate) chain[1];
            require(SUBJECT.equals(leaf.getSubjectX500Principal()) && BigInteger.ONE.equals(leaf.getSerialNumber()), "LEAF_SUBJECT_SERIAL");
            require(LAB_ROOT.equals(root.getSubjectX500Principal()), "LAB_ROOT_SUBJECT");
            require(root.getBasicConstraints() == 0, "LAB_ROOT_CA_CONSTRAINTS");
            boolean[] rootUsage = root.getKeyUsage();
            require(rootUsage != null && rootUsage.length > 6 && rootUsage[5] && rootUsage[6], "LAB_ROOT_KEY_USAGE");
            require(leaf.getBasicConstraints() == -1, "LEAF_IS_CA");
            JSONArray certificates = new JSONArray();
            for (int index = 0; index < chain.length; index++) {
                X509Certificate certificate = (X509Certificate) chain[index];
                X509Certificate issuer = (X509Certificate) chain[Math.min(index + 1, chain.length - 1)];
                require(certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()), "ISSUER_NAME");
                certificate.verify(issuer.getPublicKey());
                certificate.checkValidity();
                byte[] der = certificate.getEncoded();
                require(der.length > 0 && der.length <= 16384, "CERTIFICATE_SIZE");
                require(certificate.getExtensionValue(PROVISIONING_OID) == null, "UNEXPECTED_PROVISIONING_CLAIM");
                certificates.put(new JSONObject().put("der_base64", base64(der)).put("sha256", hex(MessageDigest.getInstance("SHA-256").digest(der)))
                        .put("subject", certificate.getSubjectX500Principal().getName()).put("issuer", certificate.getIssuerX500Principal().getName())
                        .put("valid_now", true));
            }
            require(root.getExtensionValue(ATTESTATION_OID) == null, "ROOT_ATTESTATION_EXTENSION");
            require(Arrays.equals(leaf.getPublicKey().getEncoded(), pair.getPublic().getEncoded()), "LEAF_PUBLIC_KEY_MISMATCH");
            sample.put("certificates", certificates).put("chain_signatures_valid", true).put("chain_valid_now", true)
                    .put("leaf_matches_generated_key", true).put("root_self_signature_verified", true)
                    .put("lab_root_subject_matches", true).put("full_pkix_path_validation_performed", false);

            stage = "attestation_extension";
            sample.put("attestation", describe(leaf, challenge));
            stage = "key_possession";
            byte[] payload = ("AndroidLab CNG attestation control v1\nchallenge_base64=" + supplied).getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withRSA/PSS");
            signer.initSign(pair.getPrivate()); signer.update(payload);
            byte[] signature = signer.sign();
            require(signature.length == 256, "SIGNATURE_SIZE");
            PublicKey publicKey = KeyFactory.getInstance("RSA", PUBLIC_PROVIDER)
                    .generatePublic(new X509EncodedKeySpec(leaf.getPublicKey().getEncoded()));
            RSAPublicKey rsa = (RSAPublicKey) publicKey;
            require(rsa.getModulus().bitLength() == 2048 && rsa.getPublicExponent().equals(BigInteger.valueOf(65537)), "RSA_PUBLIC_PARAMETERS");
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS", PUBLIC_PROVIDER);
            verifier.setParameter(PSS); verifier.initVerify(publicKey); verifier.update(payload);
            require(verifier.verify(signature), "SIGNATURE_INVALID");
            byte[] altered = signature.clone(); altered[altered.length - 1] ^= 1;
            verifier.initVerify(publicKey); verifier.setParameter(PSS); verifier.update(payload);
            boolean rejected;
            try { rejected = !verifier.verify(altered); } catch (SignatureException expected) { rejected = true; }
            require(rejected, "TAMPER_ACCEPTED");
            sample.put("key_possession_verified", true).put("tampered_signature_rejected", true)
                    .put("payload_base64", base64(payload)).put("signature_base64", base64(signature))
                    .put("signer_provider", signer.getProvider().getName()).put("public_verifier_provider", verifier.getProvider().getName())
                    .put("digest", "SHA-256").put("mgf1_digest", "SHA-256").put("salt_length", 32);
            complete = true;
        } catch (Exception error) {
            sample.put("error_stage", stage).put("error_type", error.getClass().getSimpleName());
            if (error instanceof CheckFailure) sample.put("check_code", ((CheckFailure) error).code);
        } finally {
            JSONObject cleanup = new JSONObject().put("owned_count", alias == null ? 0 : 1)
                    .put("removed_count", 0).put("verified", false);
            try {
                if (alias != null) {
                    require(store != null, "CLEANUP_KEYSTORE_UNAVAILABLE");
                    store.deleteEntry(alias);
                    require(!store.containsAlias(alias), "CLEANUP_ALIAS_REMAINS");
                    cleanup.put("removed_count", 1);
                }
                cleanup.put("verified", true);
            } catch (Exception error) {
                complete = false;
                cleanup.put("error_type", error.getClass().getSimpleName());
            }
            long end = System.currentTimeMillis();
            sample.put("cleanup", cleanup).put("completed_at_ms", end).put("status", complete ? "complete" : "failed");
            report.put("completed_at_ms", end).put("status", complete ? "complete" : "failed");
            write(context, report);
        }
        return complete;
    }

    private JSONObject describe(X509Certificate certificate, byte[] challenge) throws Exception {
        byte[] extension = certificate.getExtensionValue(ATTESTATION_OID);
        require(extension != null && extension.length <= 32768, "ATTESTATION_EXTENSION_ABSENT");
        Der outer = Der.one(extension);
        require(outer.tagClass == 0 && outer.tag == 4, "EXTENSION_OCTET_STRING");
        Der sequence = Der.one(outer.value);
        require(sequence.tagClass == 0 && sequence.tag == 16, "ATTESTATION_SEQUENCE");
        List<Der> fields = sequence.children();
        require(fields.size() == 8, "ATTESTATION_FIELD_COUNT");
        int[] tags = {2, 10, 2, 10, 4, 4, 16, 16};
        for (int index = 0; index < tags.length; index++)
            require(fields.get(index).tagClass == 0 && fields.get(index).tag == tags[index], "ATTESTATION_FIELD_TYPE");
        require(fields.get(0).integer() == 300 && fields.get(2).integer() == 300, "ATTESTATION_VERSION");
        require(fields.get(1).integer() == 0 && fields.get(3).integer() == 0, "ATTESTATION_NOT_SOFTWARE");
        require(Arrays.equals(fields.get(4).value, challenge), "ATTESTATION_NONCE_MISMATCH");
        require(fields.get(5).value.length == 0, "UNEXPECTED_UNIQUE_ID");
        require(fields.get(7).children().isEmpty(), "HARDWARE_AUTHORIZATIONS_PRESENT");
        byte[] applicationId = null;
        for (int authorization = 6; authorization <= 7; authorization++) {
            for (Der entry : fields.get(authorization).children()) {
                require(!(entry.tagClass == 2 && entry.tag == 704), "ROOT_OF_TRUST_PRESENT");
                if (entry.tagClass == 2 && entry.tag == 709) {
                    require(authorization == 6 && applicationId == null, "APPLICATION_ID_LOCATION");
                    Der value = Der.one(entry.value);
                    require(value.tagClass == 0 && value.tag == 4, "APPLICATION_ID_TYPE");
                    applicationId = value.value;
                }
            }
        }
        require(applicationId != null && applicationId.length > 0, "APPLICATION_ID_ABSENT");
        return new JSONObject().put("attestation_version", 300).put("attestation_security_level", 0)
                .put("keymaster_version", 300).put("keymaster_security_level", 0).put("challenge_matches", true)
                .put("root_of_trust_present", false).put("hardware_authorizations_empty", true).put("unique_id_empty", true)
                .put("attestation_application_id_base64", base64(applicationId));
    }

    private static void write(Context context, JSONObject report) throws Exception {
        AtomicFile file = new AtomicFile(new File(context.getFilesDir(), "report.json"));
        FileOutputStream output = null;
        try {
            output = file.startWrite(); output.write(report.toString(2).getBytes(StandardCharsets.UTF_8));
            file.finishWrite(output);
        } catch (Exception error) { if (output != null) file.failWrite(output); throw error; }
    }
    private static String base64(byte[] value) { return Base64.encodeToString(value, Base64.NO_WRAP); }
    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) text.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }
    private static void require(boolean condition, String code) { if (!condition) throw new CheckFailure(code); }
}
