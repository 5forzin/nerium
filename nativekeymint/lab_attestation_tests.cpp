#include "hybrid_keymint_context.h"

#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/attestation_context.h>
#include <keymaster/keymaster_tags.h>
#include <keymaster/km_openssl/attestation_record.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace keymaster;
constexpr int kVersion = 4;
constexpr uint8_t kChallenge[]{'A','n','d','r','o','i','d','L','a','b',0,'n','o','n','c','e',1,2,3,4};
constexpr uint8_t kAppId[]{0x30,0x00};
struct Result { std::string name; bool passed; int actual; int expected; };
std::vector<Result> results;
size_t wire_calls = 0;
struct PublicSample { std::vector<std::string> chain; std::string challenge, app_id, payload, signature, spki; } sample;
void Require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
void Record(const char* name, bool value) { results.push_back({name, value, value ? 0 : 1, 0}); }
void Error(const char* name, keymaster_error_t actual, keymaster_error_t expected) {
    results.push_back({name, actual == expected, actual, expected});
}
template <typename Message> void WireCopy(const Message& input, Message* output) {
    const size_t size = input.SerializedSize();
    Require(size <= 65536, "WIRE_SIZE");
    std::vector<uint8_t> bytes(std::max(size_t{1}, size));
    Require(input.Serialize(bytes.data(), bytes.data() + size) == bytes.data() + size, "WIRE_SERIALIZE");
    const uint8_t* cursor = bytes.data();
    Require(output->Deserialize(&cursor, bytes.data() + size) && cursor == bytes.data() + size, "WIRE_DESERIALIZE");
}
template <typename Request, typename Response>
std::unique_ptr<Response> Call(AndroidKeymaster& device,
        void (AndroidKeymaster::*method)(const Request&, Response*), const Request& input) {
    Request decoded(kVersion);
    WireCopy(input, &decoded);
    Response response(kVersion);
    (device.*method)(decoded, &response);
    auto output = std::make_unique<Response>(kVersion);
    WireCopy(response, output.get());
    ++wire_calls;
    return output;
}
std::string Base64(const uint8_t* bytes, size_t size) {
    std::vector<uint8_t> output(4 * ((size + 2) / 3) + 1);
    const size_t written = EVP_EncodeBlock(output.data(), bytes, size);
    Require(written + 1 == output.size(), "PUBLIC_BASE64");
    return std::string(reinterpret_cast<const char*>(output.data()), written);
}
AuthorizationSet Description(keymaster_algorithm_t algorithm, bool challenge = true,
        keymaster_padding_t padding = KM_PAD_RSA_PSS) {
    AuthorizationSet parameters;
    parameters.push_back(TAG_ALGORITHM, algorithm);
    parameters.push_back(TAG_NO_AUTH_REQUIRED);
    parameters.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
    parameters.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    if (algorithm == KM_ALGORITHM_RSA) {
        parameters.push_back(TAG_KEY_SIZE, 2048);
        parameters.push_back(TAG_RSA_PUBLIC_EXPONENT, uint64_t{65537});
        parameters.push_back(TAG_PADDING, padding);
    } else {
        parameters.push_back(TAG_KEY_SIZE, 256);
        parameters.push_back(TAG_EC_CURVE, KM_EC_CURVE_P_256);
    }
    parameters.push_back(TAG_CERTIFICATE_NOT_BEFORE, uint64_t{1704067200000ULL});
    parameters.push_back(TAG_CERTIFICATE_NOT_AFTER, uint64_t{2208988800000ULL});
    parameters.push_back(TAG_CREATION_DATETIME, uint64_t{1704067200123ULL});
    if (challenge) {
        parameters.push_back(TAG_ATTESTATION_CHALLENGE, kChallenge, sizeof(kChallenge));
        parameters.push_back(TAG_ATTESTATION_APPLICATION_ID, kAppId, sizeof(kAppId));
    }
    return parameters;
}
std::unique_ptr<GenerateKeyResponse> Generate(AndroidKeymaster& device, AuthorizationSet parameters) {
    GenerateKeyRequest request(kVersion);
    request.key_description = std::move(parameters);
    return Call(device, &AndroidKeymaster::GenerateKey, request);
}
bssl::UniquePtr<X509> Parse(const keymaster_blob_t& der) {
    if (!der.data || !der.data_length) return {};
    const uint8_t* cursor = der.data;
    bssl::UniquePtr<X509> certificate(d2i_X509(nullptr, &cursor, der.data_length));
    if (!certificate || cursor != der.data + der.data_length) return {};
    return certificate;
}
bool CngReference(const KeymasterKeyBlob& blob) {
    constexpr std::array<uint8_t, 4> prefix{{1,0,0,0}};
    return blob.size() == 36 && blob.begin() && std::equal(prefix.begin(), prefix.end(), blob.begin());
}
using DescriptionPtr = std::unique_ptr<KM_KEY_DESCRIPTION, decltype(&KM_KEY_DESCRIPTION_free)>;
DescriptionPtr Attestation(X509* certificate) {
    bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1));
    const int index = X509_get_ext_by_OBJ(certificate, oid.get(), -1);
    if (index < 0 || X509_get_ext_by_OBJ(certificate, oid.get(), index) >= 0) return {nullptr, KM_KEY_DESCRIPTION_free};
    X509_EXTENSION* extension = X509_get_ext(certificate, index);
    if (!extension || X509_EXTENSION_get_critical(extension)) return {nullptr, KM_KEY_DESCRIPTION_free};
    ASN1_OCTET_STRING* der = X509_EXTENSION_get_data(extension);
    const uint8_t* start = ASN1_STRING_get0_data(der);
    const uint8_t* cursor = start;
    const int size = ASN1_STRING_length(der);
    DescriptionPtr result(d2i_KM_KEY_DESCRIPTION(nullptr, &cursor, size), KM_KEY_DESCRIPTION_free);
    if (!result || cursor != start + size) return {nullptr, KM_KEY_DESCRIPTION_free};
    return result;
}
bool EqualBytes(const ASN1_STRING* actual, const uint8_t* expected, size_t size) {
    return actual && ASN1_STRING_length(actual) == static_cast<int>(size) &&
            std::memcmp(ASN1_STRING_get0_data(actual), expected, size) == 0;
}
struct StackDelete { void operator()(STACK_OF(X509)* value) const { sk_X509_free(value); } };
bool PathVerifies(X509* leaf, X509* root, bool trust_root) {
    bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
    bssl::UniquePtr<X509_STORE_CTX> context(X509_STORE_CTX_new());
    std::unique_ptr<STACK_OF(X509), StackDelete> untrusted(sk_X509_new_null());
    if (!store || !context || !untrusted || !sk_X509_push(untrusted.get(), root)) return false;
    if (trust_root && X509_STORE_add_cert(store.get(), root) != 1) return false;
    if (X509_STORE_CTX_init(context.get(), store.get(), leaf, untrusted.get()) != 1) return false;
    return X509_verify_cert(context.get()) == 1;
}
void CheckChain(const char* prefix, const GenerateKeyResponse& generated) {
    const auto name = [&](const char* suffix) { return std::string(prefix) + suffix; };
    Record(name("_chain_has_leaf_and_lab_root").c_str(), generated.certificate_chain.entry_count == 2);
    Require(generated.certificate_chain.entry_count == 2 && generated.certificate_chain.entries, "TWO_CERTIFICATES_REQUIRED");
    auto leaf = Parse(generated.certificate_chain.entries[0]);
    auto root = Parse(generated.certificate_chain.entries[1]);
    Require(leaf && root, "CHAIN_DER_REQUIRED");
    bssl::UniquePtr<EVP_PKEY> root_key(X509_get_pubkey(root.get()));
    Record(name("_leaf_signature_verifies").c_str(), root_key && X509_verify(leaf.get(), root_key.get()) == 1);
    Record(name("_root_self_signature_verifies").c_str(), root_key && X509_verify(root.get(), root_key.get()) == 1);
    Record(name("_issuer_matches_lab_root").c_str(), X509_NAME_cmp(X509_get_issuer_name(leaf.get()), X509_get_subject_name(root.get())) == 0);
    char common_name[96]{};
    X509_NAME_get_text_by_NID(X509_get_subject_name(root.get()), NID_commonName, common_name, sizeof(common_name));
    Record(name("_root_explicit_lab_name").c_str(), std::string(common_name) == "AndroidLab Software Attestation Root");
    int critical = -1;
    bssl::UniquePtr<BASIC_CONSTRAINTS> constraints(static_cast<BASIC_CONSTRAINTS*>(
            X509_get_ext_d2i(root.get(), NID_basic_constraints, &critical, nullptr)));
    Record(name("_root_ca_constraint").c_str(), constraints && critical == 1 && constraints->ca &&
            constraints->pathlen && ASN1_INTEGER_get(constraints->pathlen) == 0);
    bssl::UniquePtr<ASN1_BIT_STRING> usage(static_cast<ASN1_BIT_STRING*>(
            X509_get_ext_d2i(root.get(), NID_key_usage, &critical, nullptr)));
    Record(name("_root_key_cert_sign_usage").c_str(), usage && critical == 1 && ASN1_BIT_STRING_get_bit(usage.get(), 5) == 1);
    Record(name("_chain_untrusted_without_explicit_anchor").c_str(), !PathVerifies(leaf.get(), root.get(), false));
    Record(name("_chain_valid_with_temporary_explicit_lab_anchor").c_str(), PathVerifies(leaf.get(), root.get(), true));
    auto record = Attestation(leaf.get());
    Require(record != nullptr, "ATTESTATION_EXTENSION_REQUIRED");
    Record(name("_software_security_levels_only").c_str(), ASN1_ENUMERATED_get(record->attestation_security_level) == 0 &&
            ASN1_ENUMERATED_get(record->keymaster_security_level) == 0);
    Record(name("_keymint3_versions").c_str(), ASN1_INTEGER_get(record->attestation_version) == 300 &&
            ASN1_INTEGER_get(record->keymaster_version) == 300);
    Record(name("_request_challenge_bound").c_str(), EqualBytes(record->attestation_challenge, kChallenge, sizeof(kChallenge)));
    Record(name("_request_app_id_bound").c_str(), record->software_enforced &&
            EqualBytes(record->software_enforced->attestation_application_id, kAppId, sizeof(kAppId)));
    Record(name("_unknown_root_of_trust_omitted").c_str(), record->software_enforced && record->tee_enforced &&
            record->software_enforced->root_of_trust == nullptr && record->tee_enforced->root_of_trust == nullptr);
    Record(name("_hardware_authorizations_empty").c_str(), i2d_KM_AUTH_LIST(record->tee_enforced, nullptr) == 2 && generated.enforced.empty());
    Record(name("_unique_identifier_empty").c_str(), record->unique_id && ASN1_STRING_length(record->unique_id) == 0);
}
class BootErrorContext final : public AttestationContext {
 public:
    BootErrorContext(keymaster_security_level_t level, keymaster_error_t error)
        : AttestationContext(KmVersion::KEYMINT_3), level_(level), error_(error) {}
    keymaster_security_level_t GetSecurityLevel() const override { return level_; }
    const VerifiedBootParams* GetVerifiedBootParams(keymaster_error_t* error) const override { *error = error_; return nullptr; }
    KeymasterKeyBlob GetAttestationKey(keymaster_algorithm_t, keymaster_error_t* error) const override { *error = KM_ERROR_UNIMPLEMENTED; return {}; }
    CertificateChain GetAttestationChain(keymaster_algorithm_t, keymaster_error_t* error) const override { *error = KM_ERROR_UNIMPLEMENTED; return {}; }
 private:
    keymaster_security_level_t level_;
    keymaster_error_t error_;
};
void Reject(AndroidKeymaster& device, const char* name, AuthorizationSet description, keymaster_error_t expected) {
    auto output = Generate(device, std::move(description));
    Error(name, output->error, expected);
    Record((std::string(name) + "_outputs_empty").c_str(), output->key_blob.size() == 0 && output->certificate_chain.entry_count == 0);
}
void Run() {
    std::vector<uint8_t> disabled_public_root{0x01, 0x02};
    auto disabled = androidlab::CreateHybridKeymintContext(false, &disabled_public_root);
    Record("optout_clears_public_lab_root_output", disabled && disabled_public_root.empty());
    std::vector<uint8_t> public_root;
    auto context = androidlab::CreateHybridKeymintContext(true, &public_root);
    Require(!public_root.empty(), "PUBLIC_ROOT_REQUIRED");
    const std::vector<uint8_t> root_snapshot = public_root;
    keymaster_blob_t root_blob{public_root.data(), public_root.size()};
    auto published_root = Parse(root_blob);
    Record("published_lab_root_is_public_x509_certificate", published_root != nullptr);
    public_root[0] ^= 1;
    Require(context->SetSystemVersion(140000, 202309) == KM_ERROR_OK, "CONFIGURE_CONTEXT");
    AndroidKeymaster device(context.release(), 16, kVersion);
    auto cng = Generate(device, Description(KM_ALGORITHM_RSA));
    Error("cng_attested_generation", cng->error, KM_ERROR_OK);
    Require(cng->error == KM_ERROR_OK, "CNG_ATTESTATION_REQUIRED");
    Record("attested_rsa_uses_cng_reference", CngReference(cng->key_blob));
    CheckChain("cng", *cng);
    auto ec = Generate(device, Description(KM_ALGORITHM_EC));
    Error("ordinary_ec_attested_generation", ec->error, KM_ERROR_OK);
    Require(ec->error == KM_ERROR_OK, "EC_ATTESTATION_REQUIRED");
    CheckChain("ec", *ec);
    auto stock_rsa = Generate(device, Description(KM_ALGORITHM_RSA, true, KM_PAD_RSA_PKCS1_1_5_SIGN));
    Error("ordinary_stock_rsa_attested_generation", stock_rsa->error, KM_ERROR_OK);
    Require(stock_rsa->error == KM_ERROR_OK, "STOCK_RSA_ATTESTATION_REQUIRED");
    CheckChain("stock_rsa", *stock_rsa);
    const auto& root_der = cng->certificate_chain.entries[1];
    Record("published_public_root_matches_attestation_root", root_snapshot.size() == root_der.data_length &&
            std::memcmp(root_snapshot.data(), root_der.data, root_snapshot.size()) == 0);
    Record("mutating_public_root_copy_does_not_change_authority", public_root != root_snapshot &&
            root_snapshot.size() == root_der.data_length &&
            std::memcmp(root_snapshot.data(), root_der.data, root_snapshot.size()) == 0);
    Record("same_context_root_shared_across_cng_rsa_ec", root_der.data_length == ec->certificate_chain.entries[1].data_length &&
            std::memcmp(root_der.data, ec->certificate_chain.entries[1].data, root_der.data_length) == 0 &&
            root_der.data_length == stock_rsa->certificate_chain.entries[1].data_length &&
            std::memcmp(root_der.data, stock_rsa->certificate_chain.entries[1].data, root_der.data_length) == 0);
    auto leaf = Parse(cng->certificate_chain.entries[0]);
    auto root = Parse(root_der);
    bssl::UniquePtr<EVP_PKEY> root_key(X509_get_pubkey(root.get()));
    bssl::UniquePtr<EVP_PKEY> leaf_key(X509_get_pubkey(leaf.get()));
    ExportKeyRequest export_request(kVersion);
    export_request.SetKeyMaterial(cng->key_blob);
    export_request.key_format = KM_KEY_FORMAT_X509;
    auto exported = Call(device, &AndroidKeymaster::ExportKey, export_request);
    Require(exported->error == KM_ERROR_OK, "PUBLIC_EXPORT_REQUIRED");
    const uint8_t* export_cursor = exported->key_data;
    bssl::UniquePtr<EVP_PKEY> exported_key(d2i_PUBKEY(nullptr, &export_cursor, exported->key_data_length));
    Record("attestation_leaf_public_key_matches_cng_export", exported_key && leaf_key &&
            export_cursor == exported->key_data + exported->key_data_length && EVP_PKEY_cmp(exported_key.get(), leaf_key.get()) == 1);
    GetKeyCharacteristicsRequest characteristics_request(kVersion);
    characteristics_request.SetKeyMaterial(cng->key_blob);
    auto characteristics = Call(device, &AndroidKeymaster::GetKeyCharacteristics, characteristics_request);
    Record("attestation_metadata_not_operational_authorizations", characteristics->error == KM_ERROR_OK &&
            !characteristics->unenforced.Contains(TAG_ATTESTATION_CHALLENGE) &&
            !characteristics->unenforced.Contains(TAG_ATTESTATION_APPLICATION_ID) && characteristics->enforced.empty());
    BeginOperationRequest begin(kVersion);
    begin.SetKeyMaterial(cng->key_blob);
    begin.purpose = KM_PURPOSE_SIGN;
    begin.additional_params.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    begin.additional_params.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    begin.additional_params.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    begin.additional_params.push_back(TAG_AUTH_TOKEN, nullptr, 0);
    auto begun = Call(device, &AndroidKeymaster::BeginOperation, begin);
    Error("attested_cng_private_operation_begin", begun->error, KM_ERROR_OK);
    Require(begun->error == KM_ERROR_OK, "CNG_BEGIN_REQUIRED");
    const std::vector<uint8_t> payload{'A','n','d','r','o','i','d','L','a','b',0,'p','o','s','s','e','s','s','i','o','n'};
    FinishOperationRequest finish(kVersion);
    finish.op_handle = begun->op_handle;
    Require(finish.input.Reinitialize(payload.data(), payload.size()), "CNG_OPERATION_INPUT");
    auto finished = Call(device, &AndroidKeymaster::FinishOperation, finish);
    Error("attested_cng_private_operation_finish", finished->error, KM_ERROR_OK);
    Require(finished->error == KM_ERROR_OK, "CNG_SIGNATURE_REQUIRED");
    bssl::UniquePtr<EVP_MD_CTX> verifier(EVP_MD_CTX_new());
    EVP_PKEY_CTX* parameters = nullptr;
    bool verified = verifier && EVP_DigestVerifyInit(verifier.get(), &parameters, EVP_sha256(), nullptr, leaf_key.get()) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(parameters, RSA_PKCS1_PSS_PADDING) == 1 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md(parameters, EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters, 32) == 1 &&
            EVP_DigestVerify(verifier.get(), finished->output.peek_read(), finished->output.available_read(), payload.data(), payload.size()) == 1;
    Record("attested_cng_possession_signature_verifies", verified);
    export_request.key_format = KM_KEY_FORMAT_PKCS8;
    Error("attested_cng_private_export_still_rejected", Call(device, &AndroidKeymaster::ExportKey, export_request)->error,
            KM_ERROR_UNSUPPORTED_KEY_FORMAT);
    for (const auto& der : cng->certificate_chain) sample.chain.push_back(Base64(der.data, der.data_length));
    sample.challenge = Base64(kChallenge, sizeof(kChallenge));
    sample.app_id = Base64(kAppId, sizeof(kAppId));
    sample.payload = Base64(payload.data(), payload.size());
    sample.signature = Base64(finished->output.peek_read(), finished->output.available_read());
    sample.spki = Base64(exported->key_data, exported->key_data_length);

    std::vector<uint8_t> other_public_root;
    auto other_context = androidlab::CreateHybridKeymintContext(true, &other_public_root);
    Record("fresh_factory_public_root_is_distinct", !other_public_root.empty() && other_public_root != root_snapshot);
    Require(other_context->SetSystemVersion(140000, 202309) == KM_ERROR_OK, "OTHER_CONTEXT_CONFIGURE");
    AndroidKeymaster other(other_context.release(), 8, kVersion);
    auto other_key = Generate(other, Description(KM_ALGORITHM_EC));
    Require(other_key->error == KM_ERROR_OK && other_key->certificate_chain.entry_count == 2, "OTHER_ROOT_REQUIRED");
    Record("fresh_public_root_matches_its_own_attestation_chain",
            other_public_root.size() == other_key->certificate_chain.entries[1].data_length &&
            std::memcmp(other_public_root.data(), other_key->certificate_chain.entries[1].data,
                        other_public_root.size()) == 0);
    auto other_root = Parse(other_key->certificate_chain.entries[1]);
    bssl::UniquePtr<EVP_PKEY> other_root_key(X509_get_pubkey(other_root.get()));
    Record("fresh_context_has_fresh_lab_ca_key", other_root_key && EVP_PKEY_cmp(root_key.get(), other_root_key.get()) != 1);
    Record("wrong_lab_ca_rejects_leaf_signature", other_root_key && X509_verify(leaf.get(), other_root_key.get()) != 1);
    auto tampered = Parse(cng->certificate_chain.entries[0]);
    bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1));
    X509_EXTENSION* extension = X509_get_ext(tampered.get(), X509_get_ext_by_OBJ(tampered.get(), oid.get(), -1));
    ASN1_OCTET_STRING* extension_data = X509_EXTENSION_get_data(extension);
    const uint8_t* bytes = ASN1_STRING_get0_data(extension_data);
    std::vector<uint8_t> changed(bytes, bytes + ASN1_STRING_length(extension_data));
    auto position = std::search(changed.begin(), changed.end(), std::begin(kChallenge), std::end(kChallenge));
    Require(position != changed.end(), "CHALLENGE_ENCODING_REQUIRED");
    *position ^= 1;
    Require(ASN1_OCTET_STRING_set(extension_data, changed.data(), changed.size()) == 1 &&
            i2d_re_X509_tbs(tampered.get(), nullptr) > 0, "TAMPER_CHALLENGE");
    Record("tampered_challenge_breaks_leaf_signature", X509_verify(tampered.get(), root_key.get()) != 1);
    std::vector<uint8_t> changed_der(cng->certificate_chain.entries[0].data,
            cng->certificate_chain.entries[0].data + cng->certificate_chain.entries[0].data_length);
    changed_der.back() ^= 1;
    keymaster_blob_t changed_blob{changed_der.data(), changed_der.size()};
    auto changed_signature = Parse(changed_blob);
    Record("tampered_leaf_signature_rejected", changed_signature && X509_verify(changed_signature.get(), root_key.get()) != 1);
    auto ordinary = Generate(device, Description(KM_ALGORITHM_RSA, false));
    Require(ordinary->error == KM_ERROR_OK && ordinary->certificate_chain.entry_count == 1, "ORDINARY_CERTIFICATE_REQUIRED");
    auto ordinary_certificate = Parse(ordinary->certificate_chain.entries[0]);
    bssl::UniquePtr<EVP_PKEY> ordinary_public(X509_get_pubkey(ordinary_certificate.get()));
    Record("optin_no_challenge_keeps_self_signed_certificate", ordinary_public &&
            X509_verify(ordinary_certificate.get(), ordinary_public.get()) == 1 &&
            X509_get_ext_by_OBJ(ordinary_certificate.get(), oid.get(), -1) == -1);

    auto invalid = Description(KM_ALGORITHM_RSA);
    invalid.erase(invalid.find(KM_TAG_ATTESTATION_APPLICATION_ID));
    Reject(device, "missing_attestation_app_id_rejected", invalid, KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING);
    invalid = Description(KM_ALGORITHM_RSA);
    invalid.push_back(TAG_ATTESTATION_CHALLENGE, kChallenge, sizeof(kChallenge));
    Reject(device, "duplicate_attestation_challenge_rejected", invalid, KM_ERROR_INVALID_TAG);
    invalid = Description(KM_ALGORITHM_RSA);
    constexpr uint8_t identity[]{'u','n','s','u','p','p','o','r','t','e','d'};
    invalid.push_back(TAG_ATTESTATION_ID_SERIAL, identity, sizeof(identity));
    Reject(device, "device_identifier_attestation_rejected", invalid, KM_ERROR_CANNOT_ATTEST_IDS);
    invalid = Description(KM_ALGORITHM_EC);
    invalid.push_back(TAG_INCLUDE_UNIQUE_ID);
    Reject(device, "unique_id_attestation_rejected", invalid, KM_ERROR_UNIMPLEMENTED);
    invalid = Description(KM_ALGORITHM_RSA);
    invalid.push_back(TAG_DEVICE_UNIQUE_ATTESTATION);
    Reject(device, "device_unique_attestation_rejected", invalid, KM_ERROR_UNIMPLEMENTED);
    invalid = Description(KM_ALGORITHM_EC);
    invalid.push_back(TAG_RESET_SINCE_ID_ROTATION);
    Reject(device, "unique_id_reset_attestation_rejected", invalid, KM_ERROR_UNIMPLEMENTED);
    invalid = Description(KM_ALGORITHM_RSA);
    invalid.push_back(TAG_ROOT_OF_TRUST, identity, sizeof(identity));
    Reject(device, "caller_root_of_trust_rejected", invalid, KM_ERROR_UNIMPLEMENTED);
    GenerateKeyRequest external(kVersion);
    external.key_description = Description(KM_ALGORITHM_EC);
    external.attestation_signing_key_blob = KeymasterKeyBlob(cng->key_blob);
    auto external_result = Call(device, &AndroidKeymaster::GenerateKey, external);
    Error("external_attestation_key_rejected", external_result->error, KM_ERROR_UNIMPLEMENTED);
    invalid = Description(KM_ALGORITHM_RSA);
    invalid.erase(invalid.find(KM_TAG_PURPOSE));
    invalid.push_back(TAG_PURPOSE, KM_PURPOSE_ATTEST_KEY);
    Reject(device, "attestation_key_purpose_rejected", invalid, KM_ERROR_UNIMPLEMENTED);
    GenerateCsrV2Request csr(kVersion);
    auto csr_result = Call(device, &AndroidKeymaster::GenerateCsrV2, csr);
    Record("remote_provisioning_remains_unsupported", csr_result->error != KM_ERROR_OK);

    auto auths = Description(KM_ALGORITHM_RSA, false);
    const auto attest = Description(KM_ALGORITHM_RSA);
    UniquePtr<uint8_t[]> record;
    size_t record_size = 0;
    BootErrorContext hardware_unknown(KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KM_ERROR_UNIMPLEMENTED);
    Error("hardware_unknown_boot_still_fails_closed", build_attestation_record(attest, auths, {},
            hardware_unknown, &record, &record_size), KM_ERROR_UNIMPLEMENTED);
    BootErrorContext software_error(KM_SECURITY_LEVEL_SOFTWARE, KM_ERROR_UNKNOWN_ERROR);
    Error("software_other_boot_error_still_fails_closed", build_attestation_record(attest, auths, {},
            software_error, &record, &record_size), KM_ERROR_UNKNOWN_ERROR);
    BootErrorContext null_success(KM_SECURITY_LEVEL_SOFTWARE, KM_ERROR_OK);
    Error("software_null_successful_boot_params_rejected", build_attestation_record(attest, auths, {},
            null_success, &record, &record_size), KM_ERROR_UNKNOWN_ERROR);
}
}  // namespace

int main() {
    bool aborted = false;
    try { Run(); }
    catch (const std::exception& error) { aborted = true; std::cerr << error.what() << '\n'; }
    const size_t failed = std::count_if(results.begin(), results.end(), [](const Result& result) { return !result.passed; });
    std::cout << "{\"schema_version\":1,\"context\":\"optin_lab_software_attestation\",\"trust\":\"lab_owned_untrusted\","
              << "\"message_version\":4,\"advertised_security_level\":\"SOFTWARE\",\"aborted\":" << (aborted ? "true" : "false")
              << ",\"passed\":" << results.size() - failed << ",\"failed\":" << failed << ",\"wire_round_trips\":" << wire_calls
              << ",\"android_guest_integrated\":false,\"google_attestation_verified\":false,\"verified_boot_claimed\":false,\"cases\":[";
    for (size_t index = 0; index < results.size(); ++index) {
        const auto& result = results[index];
        if (index) std::cout << ',';
        std::cout << "{\"name\":\"" << result.name << "\",\"passed\":" << (result.passed ? "true" : "false")
                  << ",\"actual\":" << result.actual << ",\"expected\":" << result.expected << '}';
    }
    std::cout << "],\"public_attestation_sample\":{\"chain_der_base64\":[";
    for (size_t index = 0; index < sample.chain.size(); ++index) {
        if (index) std::cout << ',';
        std::cout << '"' << sample.chain[index] << '"';
    }
    std::cout << "],\"challenge_base64\":\"" << sample.challenge << "\",\"app_id_base64\":\"" << sample.app_id
              << "\",\"spki_base64\":\"" << sample.spki << "\",\"payload_base64\":\"" << sample.payload
              << "\",\"signature_base64\":\"" << sample.signature << "\"}}\n";
    return aborted || failed ? 1 : 0;
}
