#include "cng_keymint_context.h"

#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/keymaster_tags.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace keymaster;
constexpr int kWireVersion = 4;
constexpr uint64_t kDefaultBefore = 0;
constexpr uint64_t kDefaultAfter = 2461449600000ULL;  // 2048-01-01 UTC.
struct Result { std::string name; bool passed; int actual; int expected; };
std::vector<Result> results;
size_t wire_calls = 0;
struct PublicSample { std::string certificate, spki, payload, signature; } sample;

void Require(bool condition, const char* code) {
    if (!condition) throw std::runtime_error(code);
}
void Record(const char* name, bool condition) {
    results.push_back({name, condition, condition ? 0 : 1, 0});
}
void Error(const char* name, keymaster_error_t actual, keymaster_error_t expected) {
    results.push_back({name, actual == expected, actual, expected});
}
template <typename Message> void WireCopy(const Message& input, Message* output) {
    const size_t size = input.SerializedSize();
    Require(size <= 65536, "WIRE_SIZE");
    std::vector<uint8_t> bytes(std::max(size_t{1}, size));
    Require(input.Serialize(bytes.data(), bytes.data() + size) == bytes.data() + size,
            "WIRE_SERIALIZE");
    const uint8_t* cursor = bytes.data();
    Require(output->Deserialize(&cursor, bytes.data() + size) && cursor == bytes.data() + size,
            "WIRE_DESERIALIZE");
}
template <typename Request, typename Response>
std::unique_ptr<Response> Call(AndroidKeymaster& device,
        void (AndroidKeymaster::*method)(const Request&, Response*), const Request& input) {
    Request decoded(kWireVersion);
    WireCopy(input, &decoded);
    Response response(kWireVersion);
    (device.*method)(decoded, &response);
    auto output = std::make_unique<Response>(kWireVersion);
    WireCopy(response, output.get());
    ++wire_calls;
    return output;
}
AuthorizationSet Description(bool dates = true) {
    AuthorizationSet result;
    result.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    result.push_back(TAG_KEY_SIZE, 2048);
    result.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
    result.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    result.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    result.push_back(TAG_RSA_PUBLIC_EXPONENT, uint64_t{65537});
    result.push_back(TAG_NO_AUTH_REQUIRED);
    if (dates) {
        result.push_back(TAG_CERTIFICATE_NOT_BEFORE, kDefaultBefore);
        result.push_back(TAG_CERTIFICATE_NOT_AFTER, kDefaultAfter);
    }
    return result;
}
std::unique_ptr<GenerateKeyResponse> Generate(AndroidKeymaster& device, AuthorizationSet description) {
    GenerateKeyRequest request(kWireVersion);
    request.key_description = std::move(description);
    return Call(device, &AndroidKeymaster::GenerateKey, request);
}
void Delete(AndroidKeymaster& device, const KeymasterKeyBlob& blob) {
    DeleteKeyRequest request(kWireVersion);
    request.SetKeyMaterial(blob);
    Require(Call(device, &AndroidKeymaster::DeleteKey, request)->error == KM_ERROR_OK,
            "DELETE_KEY");
}
std::unique_ptr<ExportKeyResponse> Export(AndroidKeymaster& device, const KeymasterKeyBlob& blob) {
    ExportKeyRequest request(kWireVersion);
    request.SetKeyMaterial(blob);
    request.key_format = KM_KEY_FORMAT_X509;
    return Call(device, &AndroidKeymaster::ExportKey, request);
}
bssl::UniquePtr<X509> Parse(const uint8_t* bytes, size_t size) {
    if (!bytes || !size) return {};
    const uint8_t* cursor = bytes;
    bssl::UniquePtr<X509> result(d2i_X509(nullptr, &cursor, size));
    if (!result || cursor != bytes + size) return {};
    return result;
}
bssl::UniquePtr<X509> Certificate(const GenerateKeyResponse& generated) {
    if (generated.error != KM_ERROR_OK || generated.certificate_chain.entry_count != 1 ||
            !generated.certificate_chain.entries) return {};
    const auto& entry = generated.certificate_chain.entries[0];
    return Parse(entry.data, entry.data_length);
}
std::vector<uint8_t> Subject(const char* common_name) {
    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    Require(name && X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const uint8_t*>(common_name), -1, -1, 0) == 1, "SUBJECT_NAME");
    const int size = i2d_X509_NAME(name.get(), nullptr);
    Require(size > 0, "SUBJECT_SIZE");
    std::vector<uint8_t> output(static_cast<size_t>(size));
    uint8_t* cursor = output.data();
    Require(i2d_X509_NAME(name.get(), &cursor) == size && cursor == output.data() + output.size(),
            "SUBJECT_DER");
    return output;
}
bool SubjectMatches(X509* certificate, const std::vector<uint8_t>& der) {
    const uint8_t* cursor = der.data();
    bssl::UniquePtr<X509_NAME> expected(d2i_X509_NAME(nullptr, &cursor, der.size()));
    return expected && cursor == der.data() + der.size() &&
            X509_NAME_cmp(expected.get(), X509_get_subject_name(certificate)) == 0 &&
            X509_NAME_cmp(expected.get(), X509_get_issuer_name(certificate)) == 0;
}
bool SerialMatches(X509* certificate, const std::vector<uint8_t>& magnitude) {
    bssl::UniquePtr<BIGNUM> actual(ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), nullptr));
    bssl::UniquePtr<BIGNUM> expected(BN_bin2bn(magnitude.data(), magnitude.size(), nullptr));
    return actual && expected && !BN_is_negative(actual.get()) && BN_cmp(actual.get(), expected.get()) == 0;
}
bool DatesMatch(X509* certificate, uint64_t before, uint64_t after) {
    int64_t actual_before = -1, actual_after = -1;
    return ASN1_TIME_to_posix(X509_get0_notBefore(certificate), &actual_before) == 1 &&
            ASN1_TIME_to_posix(X509_get0_notAfter(certificate), &actual_after) == 1 &&
            actual_before == static_cast<int64_t>(before / 1000) &&
            actual_after == static_cast<int64_t>(after / 1000);
}
bool HashAlgorithm(const X509_ALGOR* algorithm, int expected_nid) {
    if (!algorithm) return false;
    const ASN1_OBJECT* object = nullptr;
    int type = V_ASN1_UNDEF;
    const void* value = nullptr;
    X509_ALGOR_get0(&object, &type, &value, algorithm);
    return object && OBJ_obj2nid(object) == expected_nid &&
            (type == V_ASN1_UNDEF || type == V_ASN1_NULL);
}
// Decode semantic parameters instead of comparing the certificate builder's DER constant.
bool PssParameters(const X509_ALGOR* algorithm) {
    if (!algorithm) return false;
    const ASN1_OBJECT* object = nullptr;
    int type = V_ASN1_UNDEF;
    const void* value = nullptr;
    X509_ALGOR_get0(&object, &type, &value, algorithm);
    if (!object || OBJ_obj2nid(object) != NID_rsassaPss || type != V_ASN1_SEQUENCE || !value)
        return false;
    const auto* sequence = static_cast<const ASN1_STRING*>(value);
    const uint8_t* start = ASN1_STRING_get0_data(sequence);
    const uint8_t* cursor = start;
    const int size = ASN1_STRING_length(sequence);
    bssl::UniquePtr<RSA_PSS_PARAMS> parameters(d2i_RSA_PSS_PARAMS(nullptr, &cursor, size));
    if (!parameters || cursor != start + size || !HashAlgorithm(parameters->hashAlgorithm, NID_sha256) ||
            !parameters->saltLength || ASN1_INTEGER_get(parameters->saltLength) != 32 ||
            (parameters->trailerField && ASN1_INTEGER_get(parameters->trailerField) != 1) ||
            !parameters->maskGenAlgorithm) return false;
    X509_ALGOR_get0(&object, &type, &value, parameters->maskGenAlgorithm);
    if (!object || OBJ_obj2nid(object) != NID_mgf1 || type != V_ASN1_SEQUENCE || !value) return false;
    sequence = static_cast<const ASN1_STRING*>(value);
    start = ASN1_STRING_get0_data(sequence);
    cursor = start;
    const int hash_size = ASN1_STRING_length(sequence);
    bssl::UniquePtr<X509_ALGOR> mask_hash(d2i_X509_ALGOR(nullptr, &cursor, hash_size));
    return mask_hash && cursor == start + hash_size && HashAlgorithm(mask_hash.get(), NID_sha256);
}
bool NoCertificateTags(const AuthorizationSet& parameters) {
    return !parameters.Contains(TAG_CERTIFICATE_SERIAL) && !parameters.Contains(TAG_CERTIFICATE_SUBJECT) &&
            !parameters.Contains(TAG_CERTIFICATE_NOT_BEFORE) && !parameters.Contains(TAG_CERTIFICATE_NOT_AFTER);
}
bool Verify(EVP_PKEY* key, const std::vector<uint8_t>& payload, const std::vector<uint8_t>& signature) {
    bssl::UniquePtr<EVP_MD_CTX> context(EVP_MD_CTX_new());
    EVP_PKEY_CTX* parameters = nullptr;
    if (!key || !context || EVP_DigestVerifyInit(context.get(), &parameters, EVP_sha256(), nullptr, key) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(parameters, RSA_PKCS1_PSS_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(parameters, EVP_sha256()) != 1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters, 32) != 1) return false;
    return EVP_DigestVerify(context.get(), signature.data(), signature.size(), payload.data(), payload.size()) == 1;
}
std::string Base64(const uint8_t* bytes, size_t size) {
    std::vector<uint8_t> encoded(4 * ((size + 2) / 3) + 1);
    const size_t written = EVP_EncodeBlock(encoded.data(), bytes, size);
    Require(written + 1 == encoded.size(), "PUBLIC_BASE64");
    return std::string(reinterpret_cast<const char*>(encoded.data()), written);
}
void RejectGeneration(AndroidKeymaster& device, const char* name, AuthorizationSet description,
        keymaster_error_t expected) {
    auto output = Generate(device, std::move(description));
    Error(name, output->error, expected);
    const std::string clean_name = std::string(name) + "_outputs_empty";
    Record(clean_name.c_str(), output->key_blob.size() == 0 && output->certificate_chain.entry_count == 0 &&
            output->enforced.empty() && output->unenforced.empty());
    if (output->error == KM_ERROR_OK) Delete(device, output->key_blob);
}

void Run() {
    auto context = androidlab::CreateCngKeymasterContext(KmVersion::KEYMINT_3);
    Record("context_keymint_3", context->GetKmVersion() == KmVersion::KEYMINT_3);
    Record("reported_security_level_software",
            static_cast<PureSoftKeymasterContext*>(context.get())->GetSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE);
    Require(context->SetSystemVersion(140000, 202310) == KM_ERROR_OK, "SET_SYSTEM_VERSION");
    AndroidKeymaster device(context.release(), 8, kWireVersion);

    const auto custom_subject = Subject("AndroidDeviceLab");
    const std::vector<uint8_t> serial{0x12, 0x34};
    constexpr uint64_t before = 1700000000123ULL, after = 1900000000456ULL;
    auto description = Description(false);
    description.push_back(TAG_CERTIFICATE_NOT_BEFORE, before);
    description.push_back(TAG_CERTIFICATE_NOT_AFTER, after);
    description.push_back(TAG_CERTIFICATE_SERIAL, serial.data(), serial.size());
    description.push_back(TAG_CERTIFICATE_SUBJECT, custom_subject.data(), custom_subject.size());
    auto generated = Generate(device, description);
    Error("generate_keymint3_wire_v4", generated->error, KM_ERROR_OK);
    Require(generated->error == KM_ERROR_OK, "GENERATION_REQUIRED");
    auto certificate = Certificate(*generated);
    Record("one_complete_der_certificate", certificate != nullptr);
    Require(certificate != nullptr, "CERTIFICATE_REQUIRED");
    Record("certificate_version_3", X509_get_version(certificate.get()) == 2);
    bssl::UniquePtr<EVP_PKEY> public_key(X509_get_pubkey(certificate.get()));
    Require(public_key != nullptr, "CERTIFICATE_PUBLIC_KEY_REQUIRED");
    Record("self_signed_certificate_verifies", X509_verify(certificate.get(), public_key.get()) == 1);
    Record("custom_subject_and_issuer", SubjectMatches(certificate.get(), custom_subject));
    Record("custom_serial", SerialMatches(certificate.get(), serial));
    Record("custom_dates_seconds_observed", DatesMatch(certificate.get(), before, after));
    const X509_ALGOR* outer = nullptr;
    X509_get0_signature(nullptr, &outer, certificate.get());
    const X509_ALGOR* inner = X509_get0_tbs_sigalg(certificate.get());
    Record("pss_outer_sha256_mgf1_sha256_salt32_trailer1", PssParameters(outer));
    Record("pss_inner_sha256_mgf1_sha256_salt32_trailer1", PssParameters(inner));
    Record("inner_outer_algorithm_identifiers_equal", outer && inner && X509_ALGOR_cmp(outer, inner) == 0);
    bssl::UniquePtr<ASN1_OBJECT> attestation_oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1));
    Record("android_attestation_extension_absent", attestation_oid &&
            X509_get_ext_by_OBJ(certificate.get(), attestation_oid.get(), -1) == -1);
    int critical = -1;
    bssl::UniquePtr<ASN1_BIT_STRING> usage(static_cast<ASN1_BIT_STRING*>(
            X509_get_ext_d2i(certificate.get(), NID_key_usage, &critical, nullptr)));
    bool signing_only = usage && critical == 1 && ASN1_BIT_STRING_get_bit(usage.get(), 0) == 1;
    for (int bit = 1; bit <= 8 && signing_only; ++bit)
        signing_only = ASN1_BIT_STRING_get_bit(usage.get(), bit) == 0;
    Record("key_usage_critical_digital_signature_only", signing_only);
    Record("generated_hardware_authorizations_empty", generated->enforced.empty());
    Record("generated_certificate_tags_not_authorizations",
            NoCertificateTags(generated->enforced) && NoCertificateTags(generated->unenforced));
    GetKeyCharacteristicsRequest characteristics_request(kWireVersion);
    characteristics_request.SetKeyMaterial(generated->key_blob);
    auto characteristics = Call(device, &AndroidKeymaster::GetKeyCharacteristics, characteristics_request);
    Error("get_characteristics_wire_v4", characteristics->error, KM_ERROR_OK);
    Record("loaded_hardware_authorizations_empty", characteristics->error == KM_ERROR_OK && characteristics->enforced.empty());
    Record("loaded_certificate_tags_not_authorizations", characteristics->error == KM_ERROR_OK &&
            NoCertificateTags(characteristics->enforced) && NoCertificateTags(characteristics->unenforced));
    keymaster_algorithm_t algorithm = KM_ALGORITHM_AES;
    Record("loaded_software_rsa_authorization", characteristics->error == KM_ERROR_OK &&
            characteristics->unenforced.GetTagValue(TAG_ALGORITHM, &algorithm) && algorithm == KM_ALGORITHM_RSA);
    auto exported = Export(device, generated->key_blob);
    Error("export_public_spki_wire_v4", exported->error, KM_ERROR_OK);
    Require(exported->error == KM_ERROR_OK, "EXPORT_REQUIRED");
    const uint8_t* export_cursor = exported->key_data;
    bssl::UniquePtr<EVP_PKEY> exported_key(d2i_PUBKEY(nullptr, &export_cursor, exported->key_data_length));
    Record("certificate_spki_matches_exported_key", exported_key &&
            export_cursor == exported->key_data + exported->key_data_length &&
            EVP_PKEY_cmp(exported_key.get(), public_key.get()) == 1);
    const int spki_size = i2d_PUBKEY(public_key.get(), nullptr);
    Require(spki_size > 0, "CERTIFICATE_SPKI_SIZE");
    std::vector<uint8_t> certificate_spki(static_cast<size_t>(spki_size));
    uint8_t* spki_cursor = certificate_spki.data();
    Record("certificate_spki_der_equals_export", i2d_PUBKEY(public_key.get(), &spki_cursor) == spki_size &&
            spki_cursor == certificate_spki.data() + certificate_spki.size() &&
            certificate_spki.size() == exported->key_data_length &&
            std::equal(certificate_spki.begin(), certificate_spki.end(), exported->key_data));
    const std::vector<uint8_t> payload{'A','n','d','r','o','i','d','D','e','v','i','c','e','L','a','b',0,0xff};
    BeginOperationRequest begin_request(kWireVersion);
    begin_request.SetKeyMaterial(generated->key_blob);
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.additional_params.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    begin_request.additional_params.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    auto begun = Call(device, &AndroidKeymaster::BeginOperation, begin_request);
    Error("begin_operational_signature_wire_v4", begun->error, KM_ERROR_OK);
    Require(begun->error == KM_ERROR_OK, "BEGIN_REQUIRED");
    FinishOperationRequest finish_request(kWireVersion);
    finish_request.op_handle = begun->op_handle;
    Require(finish_request.input.Reinitialize(payload.data(), payload.size()), "FINISH_INPUT");
    auto finished = Call(device, &AndroidKeymaster::FinishOperation, finish_request);
    Error("finish_operational_signature_wire_v4", finished->error, KM_ERROR_OK);
    Require(finished->error == KM_ERROR_OK, "FINISH_REQUIRED");
    const std::vector<uint8_t> signature(finished->output.peek_read(),
            finished->output.peek_read() + finished->output.available_read());
    Record("operational_signature_verifies_with_certificate_key", signature.size() == 256 &&
            Verify(public_key.get(), payload, signature));
    auto changed_payload = payload;
    changed_payload.back() ^= 1;
    Record("changed_operational_payload_rejected", !Verify(public_key.get(), changed_payload, signature));

    const auto& der = generated->certificate_chain.entries[0];
    std::vector<uint8_t> changed_der(der.data, der.data + der.data_length);
    changed_der.back() ^= 1;
    auto changed_certificate = Parse(changed_der.data(), changed_der.size());
    Record("tampered_certificate_signature_parses", changed_certificate != nullptr);
    Record("tampered_certificate_signature_rejected", changed_certificate &&
            X509_verify(changed_certificate.get(), public_key.get()) != 1);
    changed_der.assign(der.data, der.data + der.data_length);
    changed_der.push_back(0);
    Record("certificate_trailing_der_rejected_by_strict_parser", !Parse(changed_der.data(), changed_der.size()));
    Record("certificate_truncated_der_rejected", !Parse(der.data, der.data_length - 1));
    auto changed_tbs = Parse(der.data, der.data_length);
    Require(changed_tbs != nullptr, "TBS_COPY");
    Require(ASN1_INTEGER_set(X509_get_serialNumber(changed_tbs.get()), 999) == 1 &&
            i2d_re_X509_tbs(changed_tbs.get(), nullptr) > 0, "TBS_CHANGE");
    Record("tampered_certificate_tbs_rejected", X509_verify(changed_tbs.get(), public_key.get()) != 1);
    sample.certificate = Base64(der.data, der.data_length);
    sample.spki = Base64(exported->key_data, exported->key_data_length);
    sample.payload = Base64(payload.data(), payload.size());
    sample.signature = Base64(signature.data(), signature.size());
    Delete(device, generated->key_blob);

    auto defaults = Generate(device, Description());
    Error("generate_default_serial_subject_explicit_dates", defaults->error, KM_ERROR_OK);
    auto default_certificate = Certificate(*defaults);
    Require(default_certificate != nullptr, "DEFAULT_CERTIFICATE_REQUIRED");
    Record("default_serial_one", SerialMatches(default_certificate.get(), {1}));
    Record("default_subject_android_keystore_key",
            SubjectMatches(default_certificate.get(), Subject("Android Keystore Key")));
    Record("caller_explicit_epoch_to_2048_dates", DatesMatch(default_certificate.get(), kDefaultBefore, kDefaultAfter));
    Delete(device, defaults->key_blob);

    const std::vector<std::vector<uint8_t>> serials{{0}, std::vector<uint8_t>(20, 0x80), {0, 0, 0x12, 0x34}};
    const char* serial_names[]{"serial_zero_container_roundtrip", "serial_20_bytes_high_bit_container_roundtrip",
            "serial_leading_zero_container_roundtrip"};
    for (size_t index = 0; index < serials.size(); ++index) {
        auto parameters = Description();
        parameters.push_back(TAG_CERTIFICATE_SERIAL, serials[index].data(), serials[index].size());
        auto output = Generate(device, parameters);
        auto parsed = Certificate(*output);
        bssl::UniquePtr<EVP_PKEY> key(parsed ? X509_get_pubkey(parsed.get()) : nullptr);
        Record(serial_names[index], parsed && key && SerialMatches(parsed.get(), serials[index]) &&
                X509_verify(parsed.get(), key.get()) == 1);
        if (output->error == KM_ERROR_OK) Delete(device, output->key_blob);
    }

    auto invalid = Description(false);
    invalid.push_back(TAG_CERTIFICATE_NOT_AFTER, kDefaultAfter);
    RejectGeneration(device, "missing_not_before", invalid, KM_ERROR_MISSING_NOT_BEFORE);
    invalid = Description(false);
    invalid.push_back(TAG_CERTIFICATE_NOT_BEFORE, kDefaultBefore);
    RejectGeneration(device, "missing_not_after", invalid, KM_ERROR_MISSING_NOT_AFTER);
    invalid = Description(false);
    invalid.push_back(TAG_CERTIFICATE_NOT_BEFORE, uint64_t{2});
    invalid.push_back(TAG_CERTIFICATE_NOT_AFTER, uint64_t{1});
    RejectGeneration(device, "inverted_certificate_dates", invalid, KM_ERROR_INVALID_ARGUMENT);
    invalid = Description(false);
    invalid.push_back(TAG_CERTIFICATE_NOT_BEFORE, kDefaultBefore);
    invalid.push_back(TAG_CERTIFICATE_NOT_AFTER, uint64_t{253402300800000ULL});
    RejectGeneration(device, "certificate_date_above_year9999", invalid, KM_ERROR_INVALID_ARGUMENT);
    invalid = Description();
    invalid.push_back(TAG_CERTIFICATE_NOT_BEFORE, kDefaultBefore);
    RejectGeneration(device, "duplicate_certificate_tag", invalid, KM_ERROR_INVALID_TAG);
    auto bad_subject = custom_subject;
    bad_subject.push_back(0);
    invalid = Description();
    invalid.push_back(TAG_CERTIFICATE_SUBJECT, bad_subject.data(), bad_subject.size());
    RejectGeneration(device, "subject_der_trailing_data", invalid, KM_ERROR_INVALID_ARGUMENT);
    invalid = Description();
    invalid.push_back(TAG_CERTIFICATE_SUBJECT, custom_subject.data(), custom_subject.size() - 1);
    RejectGeneration(device, "subject_der_truncated", invalid, KM_ERROR_INVALID_ARGUMENT);
    invalid = Description();
    constexpr uint8_t challenge[]{1, 2, 3};
    invalid.push_back(TAG_ATTESTATION_CHALLENGE, challenge, sizeof(challenge));
    RejectGeneration(device, "attestation_challenge_unsupported", invalid, KM_ERROR_UNIMPLEMENTED);
    invalid = Description();
    invalid.erase(invalid.find(KM_TAG_PURPOSE));
    invalid.push_back(TAG_PURPOSE, KM_PURPOSE_ATTEST_KEY);
    RejectGeneration(device, "attest_key_purpose_unsupported", invalid, KM_ERROR_UNSUPPORTED_PURPOSE);
}
}  // namespace

int main() {
    bool aborted = false;
    try { Run(); }
    catch (...) { aborted = true; std::cerr << "KEYMINT3_CERTIFICATE_HARNESS_ABORTED\n"; }
    const size_t failed = std::count_if(results.begin(), results.end(), [](const Result& result) { return !result.passed; });
    std::cout << "{\"schema_version\":1,\"context\":\"native_android_keymaster_cng\",\"km_version\":\"3\","
              << "\"message_version\":4,\"advertised_security_level\":\"SOFTWARE\",\"aborted\":" << (aborted ? "true" : "false")
              << ",\"passed\":" << results.size() - failed << ",\"failed\":" << failed
              << ",\"wire_round_trips\":" << wire_calls
              << ",\"android_guest_integrated\":false,\"android_tee_verified\":false,\"google_attestation_verified\":false,"
              << "\"pkix_trust_established\":false,\"zero_detections_achieved\":false,\"cases\":[";
    for (size_t index = 0; index < results.size(); ++index) {
        const auto& result = results[index];
        if (index) std::cout << ',';
        std::cout << "{\"name\":\"" << result.name << "\",\"passed\":" << (result.passed ? "true" : "false")
                  << ",\"actual\":" << result.actual << ",\"comparison\":\"equal\",\"expected\":" << result.expected << '}';
    }
    std::cout << "],\"public_validation_sample\":{\"certificate_der_base64\":\"" << sample.certificate
              << "\",\"spki_der_base64\":\"" << sample.spki << "\",\"payload_base64\":\"" << sample.payload
              << "\",\"signature_base64\":\"" << sample.signature << "\"}}\n";
    return aborted || failed ? 1 : 0;
}
