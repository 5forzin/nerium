#include "hybrid_keymint_context.h"

#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/keymaster_tags.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace keymaster;
constexpr int kVersion = 4;
constexpr uint32_t kOsVersion = 140000, kOsPatchlevel = 202309, kImagePatchlevel = 20230905;
constexpr uint8_t kApplication[] = {'A','n','d','r','o','i','d','D','e','v','i','c','e','L','a','b'};
struct Result { std::string name; bool passed; int actual; int expected; };
std::vector<Result> results;
size_t wire_calls = 0;
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
AuthorizationSet Binding() {
    AuthorizationSet result;
    result.push_back(TAG_APPLICATION_ID, kApplication, sizeof(kApplication));
    return result;
}
AuthorizationSet Description(keymaster_algorithm_t algorithm) {
    AuthorizationSet result = Binding();
    result.push_back(TAG_ALGORITHM, algorithm);
    result.push_back(TAG_NO_AUTH_REQUIRED);
    if (algorithm == KM_ALGORITHM_RSA) {
        result.push_back(TAG_KEY_SIZE, 2048);
        result.push_back(TAG_RSA_PUBLIC_EXPONENT, uint64_t{65537});
        result.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
        result.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
        result.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        result.push_back(TAG_CERTIFICATE_NOT_BEFORE, uint64_t{0});
        result.push_back(TAG_CERTIFICATE_NOT_AFTER, uint64_t{2461449600000ULL});
    } else if (algorithm == KM_ALGORITHM_AES) {
        result.push_back(TAG_KEY_SIZE, 256);
        result.push_back(TAG_PURPOSE, KM_PURPOSE_ENCRYPT);
        result.push_back(TAG_PURPOSE, KM_PURPOSE_DECRYPT);
        result.push_back(TAG_BLOCK_MODE, KM_MODE_GCM);
        result.push_back(TAG_PADDING, KM_PAD_NONE);
        result.push_back(TAG_MIN_MAC_LENGTH, 128);
    } else if (algorithm == KM_ALGORITHM_HMAC) {
        result.push_back(TAG_KEY_SIZE, 256);
        result.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
        result.push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
        result.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        result.push_back(TAG_MIN_MAC_LENGTH, 128);
    }
    return result;
}
std::unique_ptr<GenerateKeyResponse> Generate(AndroidKeymaster& device, AuthorizationSet description) {
    GenerateKeyRequest request(kVersion);
    request.key_description = std::move(description);
    return Call(device, &AndroidKeymaster::GenerateKey, request);
}
std::unique_ptr<GetKeyCharacteristicsResponse> Characteristics(AndroidKeymaster& device,
        const KeymasterKeyBlob& blob, AuthorizationSet binding = Binding()) {
    GetKeyCharacteristicsRequest request(kVersion);
    request.SetKeyMaterial(blob);
    request.additional_params = std::move(binding);
    return Call(device, &AndroidKeymaster::GetKeyCharacteristics, request);
}
std::unique_ptr<BeginOperationResponse> Begin(AndroidKeymaster& device, const KeymasterKeyBlob& blob,
        keymaster_purpose_t purpose, AuthorizationSet parameters) {
    BeginOperationRequest request(kVersion);
    request.SetKeyMaterial(blob);
    request.purpose = purpose;
    request.additional_params = Binding();
    for (const auto& entry : parameters) request.additional_params.push_back(entry);
    return Call(device, &AndroidKeymaster::BeginOperation, request);
}
std::unique_ptr<FinishOperationResponse> Finish(AndroidKeymaster& device,
        keymaster_operation_handle_t handle, const std::vector<uint8_t>& input,
        const std::vector<uint8_t>& signature = {}) {
    FinishOperationRequest request(kVersion);
    request.op_handle = handle;
    if (!input.empty()) Require(request.input.Reinitialize(input.data(), input.size()), "FINISH_INPUT");
    if (!signature.empty()) Require(request.signature.Reinitialize(signature.data(), signature.size()), "FINISH_SIGNATURE");
    return Call(device, &AndroidKeymaster::FinishOperation, request);
}
std::vector<uint8_t> Bytes(const Buffer& buffer) {
    return std::vector<uint8_t>(buffer.peek_read(), buffer.peek_read() + buffer.available_read());
}
bool CngShape(const KeymasterKeyBlob& blob) {
    constexpr std::array<uint8_t, 4> prefix{{1,0,0,0}};
    return blob.size() == 36 && blob.begin() && std::equal(prefix.begin(), prefix.end(), blob.begin());
}
bool VerifyRsa(AndroidKeymaster& device, const KeymasterKeyBlob& blob,
        const std::vector<uint8_t>& payload, const Buffer& signature) {
    ExportKeyRequest request(kVersion);
    request.SetKeyMaterial(blob);
    request.key_format = KM_KEY_FORMAT_X509;
    request.additional_params = Binding();
    auto output = Call(device, &AndroidKeymaster::ExportKey, request);
    if (output->error != KM_ERROR_OK) return false;
    const uint8_t* cursor = output->key_data;
    bssl::UniquePtr<EVP_PKEY> key(d2i_PUBKEY(nullptr, &cursor, output->key_data_length));
    bssl::UniquePtr<EVP_MD_CTX> digest(EVP_MD_CTX_new());
    EVP_PKEY_CTX* parameters = nullptr;
    if (!key || cursor != output->key_data + output->key_data_length || !digest ||
            EVP_DigestVerifyInit(digest.get(), &parameters, EVP_sha256(), nullptr, key.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(parameters, RSA_PKCS1_PSS_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(parameters, EVP_sha256()) != 1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters, 32) != 1) return false;
    return EVP_DigestVerify(digest.get(), signature.peek_read(), signature.available_read(),
            payload.data(), payload.size()) == 1;
}
void Configure(KeymasterContext& context) {
    Require(context.SetSystemVersion(kOsVersion, kOsPatchlevel) == KM_ERROR_OK, "OS_CONFIGURATION");
    Require(context.SetVendorPatchlevel(kImagePatchlevel) == KM_ERROR_OK, "VENDOR_CONFIGURATION");
    Require(context.SetBootPatchlevel(kImagePatchlevel) == KM_ERROR_OK, "BOOT_CONFIGURATION");
}
void Delete(AndroidKeymaster& device, const KeymasterKeyBlob& blob) {
    DeleteKeyRequest request(kVersion);
    request.SetKeyMaterial(blob);
    Require(Call(device, &AndroidKeymaster::DeleteKey, request)->error == KM_ERROR_OK, "DELETE_KEY");
}

void Run() {
    auto legacy_context = std::make_unique<PureSoftKeymasterContext>(KmVersion::KEYMINT_3, KM_SECURITY_LEVEL_SOFTWARE);
    Configure(*legacy_context);
    AndroidKeymaster legacy(legacy_context.release(), 8, kVersion);
    auto old_aes = Generate(legacy, Description(KM_ALGORITHM_AES));
    auto old_hmac = Generate(legacy, Description(KM_ALGORITHM_HMAC));
    auto old_rsa = Generate(legacy, Description(KM_ALGORITHM_RSA));
    Require(old_aes->error == KM_ERROR_OK && old_hmac->error == KM_ERROR_OK && old_rsa->error == KM_ERROR_OK,
            "LEGACY_KEYS_REQUIRED");
    Record("legacy_aes_stock_blob", !CngShape(old_aes->key_blob));
    Record("legacy_hmac_stock_blob", !CngShape(old_hmac->key_blob));
    Record("legacy_rsa_stock_blob", !CngShape(old_rsa->key_blob));
    auto hybrid_context = androidlab::CreateHybridKeymintContext();
    Record("hybrid_keymint3_version", hybrid_context->GetKmVersion() == KmVersion::KEYMINT_3);
    Record("hybrid_remote_provisioning_absent", hybrid_context->GetRemoteProvisioningContext() == nullptr);
    Configure(*hybrid_context);
    auto* configuration = hybrid_context.get();
    auto* policy = hybrid_context->enforcement_policy();
    Require(policy != nullptr, "SHARED_POLICY_REQUIRED");
    AndroidKeymaster hybrid(hybrid_context.release(), 8, kVersion);
    Error("legacy_aes_parse_in_hybrid", Characteristics(hybrid, old_aes->key_blob)->error, KM_ERROR_OK);
    Error("legacy_hmac_parse_in_hybrid", Characteristics(hybrid, old_hmac->key_blob)->error, KM_ERROR_OK);
    Error("legacy_rsa_private_blob_parse_in_hybrid", Characteristics(hybrid, old_rsa->key_blob)->error, KM_ERROR_OK);

    const std::vector<uint8_t> payload{'A','n','d','r','o','i','d','D','e','v','i','c','e','L','a','b',0,0xff};
    AuthorizationSet aes_parameters;
    aes_parameters.push_back(TAG_BLOCK_MODE, KM_MODE_GCM);
    aes_parameters.push_back(TAG_PADDING, KM_PAD_NONE);
    aes_parameters.push_back(TAG_MAC_LENGTH, 128);
    auto encryption = Begin(hybrid, old_aes->key_blob, KM_PURPOSE_ENCRYPT, aes_parameters);
    Error("legacy_aes_encrypt_begin", encryption->error, KM_ERROR_OK);
    Require(encryption->error == KM_ERROR_OK, "AES_ENCRYPT_BEGIN_REQUIRED");
    keymaster_blob_t nonce{};
    Require(encryption->output_params.GetTagValue(TAG_NONCE, &nonce), "AES_NONCE_REQUIRED");
    auto encrypted = Finish(hybrid, encryption->op_handle, payload);
    Error("legacy_aes_encrypt_finish", encrypted->error, KM_ERROR_OK);
    Require(encrypted->error == KM_ERROR_OK, "AES_CIPHERTEXT_REQUIRED");
    aes_parameters.push_back(TAG_NONCE, nonce.data, nonce.data_length);
    auto decryption = Begin(hybrid, old_aes->key_blob, KM_PURPOSE_DECRYPT, aes_parameters);
    Error("legacy_aes_decrypt_begin", decryption->error, KM_ERROR_OK);
    Require(decryption->error == KM_ERROR_OK, "AES_DECRYPT_BEGIN_REQUIRED");
    auto decrypted = Finish(hybrid, decryption->op_handle, Bytes(encrypted->output));
    Error("legacy_aes_decrypt_finish", decrypted->error, KM_ERROR_OK);
    Record("legacy_aes_plaintext_roundtrip", decrypted->error == KM_ERROR_OK && Bytes(decrypted->output) == payload);

    AuthorizationSet hmac_parameters;
    hmac_parameters.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    hmac_parameters.push_back(TAG_MAC_LENGTH, 256);
    auto hmac_sign = Begin(hybrid, old_hmac->key_blob, KM_PURPOSE_SIGN, hmac_parameters);
    Error("legacy_hmac_sign_begin", hmac_sign->error, KM_ERROR_OK);
    Require(hmac_sign->error == KM_ERROR_OK, "HMAC_BEGIN_REQUIRED");
    auto hmac_signature = Finish(hybrid, hmac_sign->op_handle, payload);
    Error("legacy_hmac_sign", hmac_signature->error, KM_ERROR_OK);
    Require(hmac_signature->error == KM_ERROR_OK, "HMAC_SIGNATURE_REQUIRED");
    hmac_parameters.erase(hmac_parameters.find(KM_TAG_MAC_LENGTH));
    auto hmac_verify = Begin(hybrid, old_hmac->key_blob, KM_PURPOSE_VERIFY, hmac_parameters);
    Error("legacy_hmac_verify_begin", hmac_verify->error, KM_ERROR_OK);
    Require(hmac_verify->error == KM_ERROR_OK, "HMAC_VERIFY_BEGIN_REQUIRED");
    Error("legacy_hmac_verify", Finish(hybrid, hmac_verify->op_handle, payload,
            Bytes(hmac_signature->output))->error, KM_ERROR_OK);

    AuthorizationSet rsa_parameters;
    rsa_parameters.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    rsa_parameters.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    auto rsa_begin = Begin(hybrid, old_rsa->key_blob, KM_PURPOSE_SIGN, rsa_parameters);
    Error("legacy_rsa_native_factory_begin", rsa_begin->error, KM_ERROR_OK);
    Require(rsa_begin->error == KM_ERROR_OK, "LEGACY_RSA_BEGIN_REQUIRED");
    auto rsa_signature = Finish(hybrid, rsa_begin->op_handle, payload);
    Error("legacy_rsa_native_factory_sign", rsa_signature->error, KM_ERROR_OK);
    Record("legacy_rsa_signature_length", rsa_signature->output.available_read() == 256);
    Record("legacy_rsa_signature_matches_exported_public_key",
            VerifyRsa(hybrid, old_rsa->key_blob, payload, rsa_signature->output));

    auto protected_key = Generate(hybrid, Description(KM_ALGORITHM_RSA));
    Error("selected_profile_cng_generation", protected_key->error, KM_ERROR_OK);
    Require(protected_key->error == KM_ERROR_OK, "CNG_KEY_REQUIRED");
    Record("selected_profile_cng_reference_shape", CngShape(protected_key->key_blob));
    Record("protected_hardware_authorizations_empty", protected_key->enforced.empty());
    uint32_t version = 0, patchlevel = 0, vendor = 0, boot = 0;
    Record("protected_epoch_matches_explicit_source_configuration",
            protected_key->unenforced.GetTagValue(TAG_OS_VERSION, &version) && version == kOsVersion &&
            protected_key->unenforced.GetTagValue(TAG_OS_PATCHLEVEL, &patchlevel) && patchlevel == kOsPatchlevel &&
            protected_key->unenforced.GetTagValue(TAG_VENDOR_PATCHLEVEL, &vendor) && vendor == kImagePatchlevel &&
            protected_key->unenforced.GetTagValue(TAG_BOOT_PATCHLEVEL, &boot) && boot == kImagePatchlevel);
    auto protected_begin = Begin(hybrid, protected_key->key_blob, KM_PURPOSE_SIGN, rsa_parameters);
    Error("protected_native_factory_begin", protected_begin->error, KM_ERROR_OK);
    Require(protected_begin->error == KM_ERROR_OK, "CNG_BEGIN_REQUIRED");
    auto protected_signature = Finish(hybrid, protected_begin->op_handle, payload);
    Error("protected_native_factory_sign", protected_signature->error, KM_ERROR_OK);
    Record("protected_signature_length", protected_signature->output.available_read() == 256);
    Record("protected_signature_matches_exported_public_key",
            VerifyRsa(hybrid, protected_key->key_blob, payload, protected_signature->output));
    Error("cng_reference_not_accepted_by_stock_context", Characteristics(legacy, protected_key->key_blob)->error,
            KM_ERROR_INVALID_KEY_BLOB);
    auto altered = KeymasterKeyBlob(protected_key->key_blob);
    altered.writable_data()[altered.size() - 1] ^= 1;
    Error("altered_cng_reference_never_falls_back", Characteristics(hybrid, altered)->error, KM_ERROR_INVALID_KEY_BLOB);
    Error("protected_missing_binding_rejected", Characteristics(hybrid, protected_key->key_blob, {})->error,
            KM_ERROR_INVALID_KEY_BLOB);
    auto invalid_profile = Description(KM_ALGORITHM_RSA);
    invalid_profile.push_back(TAG_CERTIFICATE_NOT_BEFORE, uint64_t{0});
    Error("selected_profile_duplicate_certificate_fails_closed", Generate(hybrid, invalid_profile)->error, KM_ERROR_INVALID_TAG);
    invalid_profile = Description(KM_ALGORITHM_RSA);
    constexpr uint8_t challenge[]{1,2,3};
    invalid_profile.push_back(TAG_ATTESTATION_CHALLENGE, challenge, sizeof(challenge));
    Error("selected_profile_attestation_fails_closed", Generate(hybrid, invalid_profile)->error, KM_ERROR_UNIMPLEMENTED);

    auto new_aes = Generate(hybrid, Description(KM_ALGORITHM_AES));
    auto new_hmac = Generate(hybrid, Description(KM_ALGORITHM_HMAC));
    auto other_rsa_description = Description(KM_ALGORITHM_RSA);
    other_rsa_description.erase(other_rsa_description.find(KM_TAG_PADDING));
    other_rsa_description.push_back(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN);
    auto new_rsa = Generate(hybrid, other_rsa_description);
    Record("new_aes_keeps_stock_blob", new_aes->error == KM_ERROR_OK && !CngShape(new_aes->key_blob));
    Record("new_hmac_keeps_stock_blob", new_hmac->error == KM_ERROR_OK && !CngShape(new_hmac->key_blob));
    Record("other_rsa_profile_keeps_stock_blob", new_rsa->error == KM_ERROR_OK && !CngShape(new_rsa->key_blob));
    Require(new_aes->error == KM_ERROR_OK && new_hmac->error == KM_ERROR_OK && new_rsa->error == KM_ERROR_OK,
            "NEW_SOFTWARE_KEYS_REQUIRED");
    Error("new_software_rsa_readable_by_stock", Characteristics(legacy, new_rsa->key_blob)->error, KM_ERROR_OK);
    Record("enforcement_policy_instance_preserved", configuration->enforcement_policy() == policy);
    auto hmac_sharing = hybrid.GetHmacSharingParameters();
    GetHmacSharingParametersResponse sharing_wire(kVersion);
    WireCopy(hmac_sharing, &sharing_wire);
    Error("shared_hmac_software_policy_parameters", sharing_wire.error, KM_ERROR_OK);
    Require(sharing_wire.error == KM_ERROR_OK, "HMAC_SHARING_REQUIRED");
    ComputeSharedHmacRequest sharing_request(kVersion);
    sharing_request.params_array.params_array = new HmacSharingParameters[1];
    sharing_request.params_array.num_params = 1;
    WireCopy(sharing_wire.params, &sharing_request.params_array.params_array[0]);
    ComputeSharedHmacRequest decoded_sharing(kVersion);
    WireCopy(sharing_request, &decoded_sharing);
    auto sharing_result = hybrid.ComputeSharedHmac(decoded_sharing);
    ComputeSharedHmacResponse sharing_result_wire(kVersion);
    WireCopy(sharing_result, &sharing_result_wire);
    ++wire_calls;
    Error("shared_hmac_uses_same_software_policy", sharing_result_wire.error, KM_ERROR_OK);
    Record("shared_hmac_check_sha256_length", sharing_result_wire.error == KM_ERROR_OK &&
            sharing_result_wire.sharing_check.size() == 32);

    Require(configuration->SetSystemVersion(kOsVersion, kOsPatchlevel + 1) == KM_ERROR_OK, "EPOCH_CHANGE");
    Error("protected_old_epoch_requires_upgrade", Characteristics(hybrid, protected_key->key_blob)->error,
            KM_ERROR_KEY_REQUIRES_UPGRADE);
    Error("legacy_old_epoch_requires_upgrade", Characteristics(hybrid, old_rsa->key_blob)->error,
            KM_ERROR_KEY_REQUIRES_UPGRADE);
    UpgradeKeyRequest upgrade(kVersion);
    upgrade.SetKeyMaterial(old_rsa->key_blob);
    upgrade.upgrade_params = Binding();
    auto upgraded = Call(hybrid, &AndroidKeymaster::UpgradeKey, upgrade);
    Error("legacy_software_epoch_upgrade_preserved", upgraded->error, KM_ERROR_OK);
    Require(upgraded->error == KM_ERROR_OK, "LEGACY_UPGRADE_REQUIRED");
    Error("legacy_upgraded_blob_loads", Characteristics(hybrid, KeymasterKeyBlob(upgraded->upgraded_key))->error, KM_ERROR_OK);
    upgrade.SetKeyMaterial(protected_key->key_blob);
    Error("protected_epoch_upgrade_not_silently_rewritten", Call(hybrid, &AndroidKeymaster::UpgradeKey, upgrade)->error,
            KM_ERROR_KEY_REQUIRES_UPGRADE);
    Delete(hybrid, protected_key->key_blob);
    Error("deleted_cng_reference_never_falls_back", Characteristics(hybrid, protected_key->key_blob)->error,
            KM_ERROR_INVALID_KEY_BLOB);
    Delete(hybrid, new_aes->key_blob);
    Delete(hybrid, new_hmac->key_blob);
    Delete(hybrid, new_rsa->key_blob);
}

void RunCreationMetadataControls() {
    auto context = androidlab::CreateHybridKeymintContext();
    Configure(*context);
    AndroidKeymaster device(context.release(), 8, kVersion);
    constexpr uint64_t creation_time = 1704067200123ULL;
    auto description = Description(KM_ALGORITHM_RSA);
    description.push_back(TAG_CREATION_DATETIME, creation_time);
    auto generated = Generate(device, description);
    Error("jca_creation_datetime_generation", generated->error, KM_ERROR_OK);
    Require(generated->error == KM_ERROR_OK, "JCA_METADATA_KEY_REQUIRED");
    Record("jca_creation_datetime_keeps_cng_reference", CngShape(generated->key_blob));
    uint64_t saved_time = 0;
    Record("jca_creation_datetime_preserved_in_generation", generated->unenforced.GetTagValue(
            TAG_CREATION_DATETIME, &saved_time) && saved_time == creation_time);
    auto characteristics = Characteristics(device, generated->key_blob);
    Error("jca_creation_datetime_key_loads", characteristics->error, KM_ERROR_OK);
    Record("jca_creation_datetime_preserved_after_load", characteristics->error == KM_ERROR_OK &&
            characteristics->unenforced.GetTagValue(TAG_CREATION_DATETIME, &saved_time) && saved_time == creation_time);
    bool valid_certificate = false;
    if (generated->certificate_chain.entry_count == 1 && generated->certificate_chain.entries) {
        const auto& der = generated->certificate_chain.entries[0];
        const uint8_t* cursor = der.data;
        bssl::UniquePtr<X509> certificate(d2i_X509(nullptr, &cursor, der.data_length));
        bssl::UniquePtr<EVP_PKEY> key(certificate ? X509_get_pubkey(certificate.get()) : nullptr);
        valid_certificate = certificate && cursor == der.data + der.data_length && key &&
                X509_verify(certificate.get(), key.get()) == 1;
    }
    Record("jca_creation_datetime_certificate_self_signature_verifies", valid_certificate);
    AuthorizationSet operation;
    operation.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    operation.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    auto begun = Begin(device, generated->key_blob, KM_PURPOSE_SIGN, operation);
    Error("jca_creation_datetime_sign_begin", begun->error, KM_ERROR_OK);
    Require(begun->error == KM_ERROR_OK, "JCA_METADATA_BEGIN_REQUIRED");
    const std::vector<uint8_t> payload{'j','c','a',0,'m','e','t','a','d','a','t','a'};
    auto finished = Finish(device, begun->op_handle, payload);
    Error("jca_creation_datetime_sign_finish", finished->error, KM_ERROR_OK);
    Record("jca_creation_datetime_operational_signature_verifies", finished->error == KM_ERROR_OK &&
            VerifyRsa(device, generated->key_blob, payload, finished->output));
    auto invalid = description;
    invalid.push_back(TAG_CREATION_DATETIME, creation_time);
    Error("duplicate_creation_datetime_fails_closed", Generate(device, invalid)->error, KM_ERROR_INVALID_TAG);
    invalid = Description(KM_ALGORITHM_RSA);
    const auto wrong_type = static_cast<keymaster_tag_t>(KM_UINT | keymaster_tag_mask_type(KM_TAG_CREATION_DATETIME));
    invalid.push_back(keymaster_param_int(wrong_type, 1));
    Error("wrong_creation_datetime_type_fails_closed", Generate(device, invalid)->error, KM_ERROR_INVALID_TAG);
    invalid = Description(KM_ALGORITHM_RSA);
    invalid.push_back(TAG_CREATION_DATETIME, static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1);
    Error("negative_aidl_creation_datetime_fails_closed", Generate(device, invalid)->error, KM_ERROR_INVALID_ARGUMENT);
    Delete(device, generated->key_blob);
}
}  // namespace

int main() {
    bool aborted = false;
    try { Run(); RunCreationMetadataControls(); } catch (...) { aborted = true; std::cerr << "HYBRID_KEYMINT_HARNESS_ABORTED\n"; }
    const size_t failed = std::count_if(results.begin(), results.end(), [](const Result& result) { return !result.passed; });
    std::cout << "{\"schema_version\":1,\"context\":\"hybrid_keymint3_cng_and_stock_software\","
              << "\"message_version\":4,\"advertised_security_level\":\"SOFTWARE\",\"aborted\":" << (aborted ? "true" : "false")
              << ",\"passed\":" << results.size() - failed << ",\"failed\":" << failed
              << ",\"wire_round_trips\":" << wire_calls
              << ",\"configured_os_version\":" << kOsVersion << ",\"configured_os_patchlevel\":" << kOsPatchlevel
              << ",\"configured_vendor_patchlevel\":" << kImagePatchlevel << ",\"configured_boot_patchlevel\":" << kImagePatchlevel
              << ",\"android_guest_integrated\":false,\"existing_guest_blobs_verified\":false,\"android_tee_verified\":false,"
              << "\"google_attestation_verified\":false,\"cases\":[";
    for (size_t index = 0; index < results.size(); ++index) {
        const auto& result = results[index];
        if (index) std::cout << ',';
        std::cout << "{\"name\":\"" << result.name << "\",\"passed\":" << (result.passed ? "true" : "false")
                  << ",\"actual\":" << result.actual << ",\"expected\":" << result.expected << '}';
    }
    std::cout << "]}\n";
    return aborted || failed ? 1 : 0;
}
