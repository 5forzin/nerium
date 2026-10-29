#include "cng_keymint_context.h"

#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/keymaster_context.h>
#include <keymaster/keymaster_tags.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace keymaster;
constexpr int kWireVersion = kDefaultMessageVersion;
constexpr uint8_t kAppId[] = {0x61, 0x70, 0x70, 0x00, 0x31};
constexpr uint8_t kAppData[] = {0x64, 0x61, 0x74, 0x61, 0xff};
struct Result { std::string name; bool passed; int actual; int expected; bool nonzero; };
std::vector<Result> results;
size_t wire_calls = 0;

void Require(bool condition, const char* code) { if (!condition) throw std::runtime_error(code); }
void Record(const char* name, bool condition) { results.push_back({name, condition, condition ? 0 : 1, 0, false}); }
void Error(const char* name, keymaster_error_t actual, keymaster_error_t expected) {
    results.push_back({name, actual == expected, actual, expected, false});
}
void Rejected(const char* name, keymaster_error_t actual) {
    results.push_back({name, actual != KM_ERROR_OK, actual, 0, true});
}
bool SameAuthorizations(const AuthorizationSet& left, const AuthorizationSet& right) {
    if (left.SerializedSize() != right.SerializedSize()) return false;
    std::vector<uint8_t> a(left.SerializedSize()), b(right.SerializedSize());
    return left.Serialize(a.data(), a.data() + a.size()) == a.data() + a.size()
            && right.Serialize(b.data(), b.data() + b.size()) == b.data() + b.size() && a == b;
}

template <typename Message> void WireCopy(const Message& input, Message* output,
        const char* deserialize_error = "WIRE_DESERIALIZE") {
    const size_t size = input.SerializedSize();
    std::vector<uint8_t> bytes(std::max(size_t{1}, size));
    Require(size <= 65536, "WIRE_SIZE");
    Require(input.Serialize(bytes.data(), bytes.data() + size) == bytes.data() + size, "WIRE_SERIALIZE");
    const uint8_t* cursor = bytes.data();
    Require(output->Deserialize(&cursor, bytes.data() + size) && cursor == bytes.data() + size, deserialize_error);
}
template <typename Request, typename Response>
std::unique_ptr<Response> Call(AndroidKeymaster& device,
        void (AndroidKeymaster::*method)(const Request&, Response*), const Request& input) {
    Request decoded(input.message_version);
    WireCopy(input, &decoded, "WIRE_REQUEST_DESERIALIZE");
    Response response(input.message_version);
    (device.*method)(decoded, &response);
    auto decoded_response = std::make_unique<Response>(input.message_version);
    WireCopy(response, decoded_response.get(), "WIRE_RESPONSE_DESERIALIZE");
    ++wire_calls;
    return decoded_response;
}

AuthorizationSet Description() {
    AuthorizationSet result;
    result.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    result.push_back(TAG_KEY_SIZE, 2048);
    result.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
    result.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    result.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    result.push_back(TAG_RSA_PUBLIC_EXPONENT, uint64_t{65537});
    result.push_back(TAG_NO_AUTH_REQUIRED);
    result.push_back(TAG_APPLICATION_ID, kAppId, sizeof(kAppId));
    result.push_back(TAG_APPLICATION_DATA, kAppData, sizeof(kAppData));
    return result;
}
AuthorizationSet Bindings() {
    AuthorizationSet result;
    result.push_back(TAG_APPLICATION_ID, kAppId, sizeof(kAppId));
    result.push_back(TAG_APPLICATION_DATA, kAppData, sizeof(kAppData));
    return result;
}
std::unique_ptr<GenerateKeyResponse> Generate(AndroidKeymaster& device, AuthorizationSet description) {
    GenerateKeyRequest request(kWireVersion);
    request.key_description = std::move(description);
    return Call(device, &AndroidKeymaster::GenerateKey, request);
}
std::unique_ptr<GetKeyCharacteristicsResponse> Characteristics(AndroidKeymaster& device,
        const KeymasterKeyBlob& blob, AuthorizationSet bindings = Bindings()) {
    GetKeyCharacteristicsRequest request(kWireVersion);
    request.SetKeyMaterial(blob);
    request.additional_params = std::move(bindings);
    return Call(device, &AndroidKeymaster::GetKeyCharacteristics, request);
}
std::unique_ptr<BeginOperationResponse> Begin(AndroidKeymaster& device, const KeymasterKeyBlob& blob,
        keymaster_digest_t digest = KM_DIGEST_SHA_2_256, keymaster_padding_t padding = KM_PAD_RSA_PSS,
        keymaster_purpose_t purpose = KM_PURPOSE_SIGN) {
    BeginOperationRequest request(kWireVersion);
    request.SetKeyMaterial(blob);
    request.purpose = purpose;
    request.additional_params = Bindings();
    request.additional_params.push_back(TAG_DIGEST, digest);
    request.additional_params.push_back(TAG_PADDING, padding);
    return Call(device, &AndroidKeymaster::BeginOperation, request);
}
std::unique_ptr<FinishOperationResponse> Finish(AndroidKeymaster& device,
        keymaster_operation_handle_t handle, const uint8_t* data = nullptr, size_t size = 0) {
    FinishOperationRequest request(kWireVersion);
    request.op_handle = handle;
    if (size) Require(request.input.Reinitialize(data, size), "FINISH_INPUT_ALLOCATION");
    return Call(device, &AndroidKeymaster::FinishOperation, request);
}
std::unique_ptr<DeleteKeyResponse> Delete(AndroidKeymaster& device, const KeymasterKeyBlob& blob) {
    DeleteKeyRequest request(kWireVersion);
    request.SetKeyMaterial(blob);
    return Call(device, &AndroidKeymaster::DeleteKey, request);
}
std::unique_ptr<ExportKeyResponse> Export(AndroidKeymaster& device, const KeymasterKeyBlob& blob,
        keymaster_key_format_t format) {
    ExportKeyRequest request(kWireVersion);
    request.SetKeyMaterial(blob);
    request.additional_params = Bindings();
    request.key_format = format;
    return Call(device, &AndroidKeymaster::ExportKey, request);
}
bool Verify(const uint8_t* spki, size_t spki_size, const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature) {
    const uint8_t* cursor = spki;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(d2i_PUBKEY(nullptr, &cursor, spki_size), EVP_PKEY_free);
    if (!key || cursor != spki + spki_size) return false;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* parameters = nullptr;
    if (!context || EVP_DigestVerifyInit(context.get(), &parameters, EVP_sha256(), nullptr, key.get()) != 1
            || EVP_PKEY_CTX_set_rsa_padding(parameters, RSA_PKCS1_PSS_PADDING) != 1
            || EVP_PKEY_CTX_set_rsa_mgf1_md(parameters, EVP_sha256()) != 1
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters, 32) != 1) return false;
    return EVP_DigestVerify(context.get(), signature.data(), signature.size(), payload.data(), payload.size()) == 1;
}

void RunHalCompatibilityControls() {
    constexpr int version = 4;
    auto context = androidlab::CreateCngKeymasterContext(KmVersion::KEYMINT_3);
    Require(context->SetSystemVersion(140000, 202309) == KM_ERROR_OK, "HAL_CONTEXT_VERSION");
    AndroidKeymaster device(context.release(), 8, version);
    auto description = Description();
    description.erase(description.find(KM_TAG_APPLICATION_ID));
    description.erase(description.find(KM_TAG_APPLICATION_DATA));
    description.push_back(TAG_APPLICATION_ID, nullptr, 0);
    description.push_back(TAG_APPLICATION_DATA, nullptr, 0);
    description.push_back(TAG_CERTIFICATE_NOT_BEFORE, uint64_t{0});
    description.push_back(TAG_CERTIFICATE_NOT_AFTER, uint64_t{2461449600000ULL});
    const auto generate = [&](AuthorizationSet parameters) {
        GenerateKeyRequest request(version);
        request.key_description = std::move(parameters);
        return Call(device, &AndroidKeymaster::GenerateKey, request);
    };
    const auto characteristics = [&](const KeymasterKeyBlob& blob, AuthorizationSet bindings) {
        GetKeyCharacteristicsRequest request(version);
        request.SetKeyMaterial(blob);
        request.additional_params = std::move(bindings);
        return Call(device, &AndroidKeymaster::GetKeyCharacteristics, request);
    };
    auto generated = generate(description);
    Error("hal_empty_bindings_generation_v4", generated->error, KM_ERROR_OK);
    Require(generated->error == KM_ERROR_OK, "HAL_GENERATION_REQUIRED");
    Error("hal_empty_bindings_omitted_on_load", characteristics(generated->key_blob, {})->error, KM_ERROR_OK);
    AuthorizationSet empty_bindings;
    empty_bindings.push_back(TAG_APPLICATION_ID, nullptr, 0);
    empty_bindings.push_back(TAG_APPLICATION_DATA, nullptr, 0);
    Error("hal_empty_bindings_present_on_load", characteristics(generated->key_blob, empty_bindings)->error, KM_ERROR_OK);
    auto duplicate_bindings = empty_bindings;
    duplicate_bindings.push_back(TAG_APPLICATION_ID, nullptr, 0);
    Error("hal_duplicate_empty_binding_rejected", characteristics(generated->key_blob, duplicate_bindings)->error,
            KM_ERROR_INVALID_KEY_BLOB);
    auto duplicate_description = description;
    duplicate_description.push_back(TAG_APPLICATION_DATA, nullptr, 0);
    Error("hal_duplicate_empty_binding_generation_rejected", generate(duplicate_description)->error, KM_ERROR_INVALID_TAG);
    auto absent_description = description;
    absent_description.erase(absent_description.find(KM_TAG_APPLICATION_ID));
    absent_description.erase(absent_description.find(KM_TAG_APPLICATION_DATA));
    auto absent_key = generate(absent_description);
    Require(absent_key->error == KM_ERROR_OK, "HAL_ABSENT_BINDING_KEY_REQUIRED");
    Error("hal_absent_bindings_accept_explicit_empty", characteristics(absent_key->key_blob, empty_bindings)->error, KM_ERROR_OK);

    ExportKeyRequest export_request(version);
    export_request.SetKeyMaterial(generated->key_blob);
    export_request.key_format = KM_KEY_FORMAT_X509;
    auto exported = Call(device, &AndroidKeymaster::ExportKey, export_request);
    Require(exported->error == KM_ERROR_OK, "HAL_PUBLIC_EXPORT_REQUIRED");
    const std::vector<uint8_t> payload{'h','a','l',0,'n','o','a','u','t','h',0xff};
    const std::vector<uint8_t> ignored_token{0xff,0x00,0x7f};
    const auto begin = [&](AuthorizationSet parameters) {
        BeginOperationRequest request(version);
        request.SetKeyMaterial(generated->key_blob);
        request.purpose = KM_PURPOSE_SIGN;
        request.additional_params.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        request.additional_params.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
        for (const auto& entry : parameters) request.additional_params.push_back(entry);
        return Call(device, &AndroidKeymaster::BeginOperation, request);
    };
    AuthorizationSet empty_token;
    empty_token.push_back(TAG_AUTH_TOKEN, nullptr, 0);
    auto begun = begin(empty_token);
    Error("hal_absent_authentication_begin_empty_auxiliary_token", begun->error, KM_ERROR_OK);
    Require(begun->error == KM_ERROR_OK, "HAL_EMPTY_TOKEN_BEGIN_REQUIRED");
    UpdateOperationRequest update(version);
    update.op_handle = begun->op_handle;
    update.additional_params.push_back(TAG_AUTH_TOKEN, ignored_token.data(), ignored_token.size());
    Require(update.input.Reinitialize(payload.data(), 3), "HAL_UPDATE_INPUT");
    auto updated = Call(device, &AndroidKeymaster::UpdateOperation, update);
    Error("hal_noauth_update_ignores_auxiliary_token", updated->error, KM_ERROR_OK);
    Record("hal_noauth_update_consumes_input", updated->error == KM_ERROR_OK && updated->input_consumed == 3);
    FinishOperationRequest finish(version);
    finish.op_handle = begun->op_handle;
    finish.additional_params.push_back(TAG_AUTH_TOKEN, ignored_token.data(), ignored_token.size());
    Require(finish.input.Reinitialize(payload.data() + 3, payload.size() - 3), "HAL_FINISH_INPUT");
    auto finished = Call(device, &AndroidKeymaster::FinishOperation, finish);
    Error("hal_noauth_finish_ignores_auxiliary_token", finished->error, KM_ERROR_OK);
    Require(finished->error == KM_ERROR_OK, "HAL_TOKEN_SIGNATURE_REQUIRED");
    const std::vector<uint8_t> signature(finished->output.peek_read(),
            finished->output.peek_read() + finished->output.available_read());
    Record("hal_auxiliary_token_flow_signature_verifies", Verify(exported->key_data,
            exported->key_data_length, payload, signature));
    AuthorizationSet nonempty_token;
    nonempty_token.push_back(TAG_AUTH_TOKEN, ignored_token.data(), ignored_token.size());
    auto nonempty_begin = begin(nonempty_token);
    Error("hal_noauth_begin_ignores_unvalidated_auxiliary_token", nonempty_begin->error, KM_ERROR_OK);
    Require(nonempty_begin->error == KM_ERROR_OK, "HAL_NONEMPTY_TOKEN_BEGIN_REQUIRED");
    FinishOperationRequest empty_finish(version);
    empty_finish.op_handle = nonempty_begin->op_handle;
    empty_finish.additional_params = empty_token;
    Error("hal_noauth_finish_accepts_empty_auxiliary_token",
            Call(device, &AndroidKeymaster::FinishOperation, empty_finish)->error, KM_ERROR_OK);
    auto duplicate_token = nonempty_token;
    duplicate_token.push_back(TAG_AUTH_TOKEN, nullptr, 0);
    Error("hal_duplicate_begin_auth_token_rejected", begin(duplicate_token)->error, KM_ERROR_INVALID_TAG);
    auto active = begin(empty_token);
    Require(active->error == KM_ERROR_OK, "HAL_NEGATIVE_UPDATE_BEGIN");
    UpdateOperationRequest invalid_update(version);
    invalid_update.op_handle = active->op_handle;
    invalid_update.additional_params = duplicate_token;
    Error("hal_duplicate_update_auth_token_rejected",
            Call(device, &AndroidKeymaster::UpdateOperation, invalid_update)->error, KM_ERROR_INVALID_TAG);
    active = begin(empty_token);
    Require(active->error == KM_ERROR_OK, "HAL_NEGATIVE_FINISH_BEGIN");
    FinishOperationRequest invalid_finish(version);
    invalid_finish.op_handle = active->op_handle;
    invalid_finish.additional_params = duplicate_token;
    Error("hal_duplicate_finish_auth_token_rejected",
            Call(device, &AndroidKeymaster::FinishOperation, invalid_finish)->error, KM_ERROR_INVALID_TAG);
    AuthorizationSet wrong_parameters;
    wrong_parameters.push_back(TAG_MAC_LENGTH, 128);
    Error("hal_incompatible_begin_parameter_rejected", begin(wrong_parameters)->error, KM_ERROR_UNSUPPORTED_TAG);
    active = begin(empty_token);
    Require(active->error == KM_ERROR_OK, "HAL_UNSUPPORTED_UPDATE_BEGIN");
    invalid_update.op_handle = active->op_handle;
    invalid_update.additional_params = wrong_parameters;
    Error("hal_incompatible_update_parameter_rejected",
            Call(device, &AndroidKeymaster::UpdateOperation, invalid_update)->error, KM_ERROR_UNSUPPORTED_TAG);
    active = begin(empty_token);
    Require(active->error == KM_ERROR_OK, "HAL_UNSUPPORTED_FINISH_BEGIN");
    invalid_finish.op_handle = active->op_handle;
    invalid_finish.additional_params = wrong_parameters;
    Error("hal_incompatible_finish_parameter_rejected",
            Call(device, &AndroidKeymaster::FinishOperation, invalid_finish)->error, KM_ERROR_UNSUPPORTED_TAG);

    auto mixed_description = description;
    mixed_description.erase(mixed_description.find(KM_TAG_APPLICATION_DATA));
    mixed_description.push_back(TAG_APPLICATION_DATA, kAppData, sizeof(kAppData));
    auto mixed_key = generate(mixed_description);
    Require(mixed_key->error == KM_ERROR_OK, "HAL_MIXED_BINDING_KEY_REQUIRED");
    AuthorizationSet data_only;
    data_only.push_back(TAG_APPLICATION_DATA, kAppData, sizeof(kAppData));
    Error("hal_empty_id_preserves_nonempty_data_binding", characteristics(mixed_key->key_blob, data_only)->error, KM_ERROR_OK);
    Error("hal_nonempty_data_binding_still_required", characteristics(mixed_key->key_blob, {})->error, KM_ERROR_INVALID_KEY_BLOB);
    DeleteKeyRequest delete_request(version);
    delete_request.SetKeyMaterial(mixed_key->key_blob);
    Error("hal_successful_release_deletes_reference", Call(device, &AndroidKeymaster::DeleteKey, delete_request)->error, KM_ERROR_OK);
    Error("hal_successful_release_reference_unusable", characteristics(mixed_key->key_blob, data_only)->error, KM_ERROR_INVALID_KEY_BLOB);
    DeleteAllKeysRequest delete_all(version);
    Error("hal_successful_release_all_keys", Call(device, &AndroidKeymaster::DeleteAllKeys, delete_all)->error, KM_ERROR_OK);
    Error("hal_release_all_first_reference_unusable", characteristics(generated->key_blob, {})->error, KM_ERROR_INVALID_KEY_BLOB);
    Error("hal_release_all_second_reference_unusable", characteristics(absent_key->key_blob, {})->error, KM_ERROR_INVALID_KEY_BLOB);
}

void RunJcaBeginControls() {
    constexpr int version = 4;
    auto context = androidlab::CreateCngKeymasterContext(KmVersion::KEYMINT_3);
    Require(context->SetSystemVersion(140000, 202309) == KM_ERROR_OK, "JCA_BEGIN_CONTEXT_VERSION");
    AndroidKeymaster device(context.release(), 8, version);
    auto description = Description();
    description.erase(description.find(KM_TAG_APPLICATION_ID));
    description.erase(description.find(KM_TAG_APPLICATION_DATA));
    description.push_back(TAG_CERTIFICATE_NOT_BEFORE, uint64_t{0});
    description.push_back(TAG_CERTIFICATE_NOT_AFTER, uint64_t{2461449600000ULL});
    GenerateKeyRequest generation(version);
    generation.key_description = description;
    auto generated = Call(device, &AndroidKeymaster::GenerateKey, generation);
    Require(generated->error == KM_ERROR_OK, "JCA_BEGIN_KEY_REQUIRED");
    const auto request_parameters = [] {
        AuthorizationSet parameters;
        parameters.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        parameters.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        parameters.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
        parameters.push_back(TAG_AUTH_TOKEN, nullptr, 0);
        return parameters;
    };
    BeginOperationRequest request(version);
    request.SetKeyMaterial(generated->key_blob);
    request.purpose = KM_PURPOSE_SIGN;
    request.additional_params = request_parameters();
    Record("jca_rsa_pss_begin_wire_payload_exactly_92_bytes", request.SerializedSize() == 92);
    auto begun = Call(device, &AndroidKeymaster::BeginOperation, request);
    Error("jca_rsa_pss_algorithm_parameter_begin", begun->error, KM_ERROR_OK);
    Require(begun->error == KM_ERROR_OK, "JCA_BEGIN_REQUIRED");
    const std::vector<uint8_t> payload{'j','c','a',0,'r','s','a','p','s','s'};
    FinishOperationRequest finish(version);
    finish.op_handle = begun->op_handle;
    Require(finish.input.Reinitialize(payload.data(), payload.size()), "JCA_FINISH_INPUT");
    auto finished = Call(device, &AndroidKeymaster::FinishOperation, finish);
    Error("jca_rsa_pss_algorithm_parameter_finish", finished->error, KM_ERROR_OK);
    Require(finished->error == KM_ERROR_OK, "JCA_BEGIN_SIGNATURE_REQUIRED");
    ExportKeyRequest export_request(version);
    export_request.SetKeyMaterial(generated->key_blob);
    export_request.key_format = KM_KEY_FORMAT_X509;
    auto exported = Call(device, &AndroidKeymaster::ExportKey, export_request);
    Require(exported->error == KM_ERROR_OK, "JCA_BEGIN_PUBLIC_KEY_REQUIRED");
    const std::vector<uint8_t> signature(finished->output.peek_read(),
            finished->output.peek_read() + finished->output.available_read());
    Record("jca_rsa_pss_92_byte_begin_signature_verifies", Verify(exported->key_data,
            exported->key_data_length, payload, signature));
    request.additional_params = request_parameters();
    request.additional_params.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    Error("jca_duplicate_begin_algorithm_rejected", Call(device, &AndroidKeymaster::BeginOperation, request)->error,
            KM_ERROR_INVALID_TAG);
    request.additional_params = request_parameters();
    request.additional_params.erase(request.additional_params.find(KM_TAG_ALGORITHM));
    request.additional_params.push_back(TAG_ALGORITHM, KM_ALGORITHM_AES);
    Error("jca_mismatched_begin_algorithm_rejected", Call(device, &AndroidKeymaster::BeginOperation, request)->error,
            KM_ERROR_INCOMPATIBLE_ALGORITHM);
    request.additional_params = request_parameters();
    request.additional_params.erase(request.additional_params.find(KM_TAG_ALGORITHM));
    const auto wrong_type = static_cast<keymaster_tag_t>(KM_UINT | keymaster_tag_mask_type(KM_TAG_ALGORITHM));
    request.additional_params.push_back(keymaster_param_int(wrong_type, KM_ALGORITHM_RSA));
    Error("jca_wrong_begin_algorithm_type_rejected", Call(device, &AndroidKeymaster::BeginOperation, request)->error,
            KM_ERROR_INVALID_TAG);
    DeleteKeyRequest deletion(version);
    deletion.SetKeyMaterial(generated->key_blob);
    Require(Call(device, &AndroidKeymaster::DeleteKey, deletion)->error == KM_ERROR_OK, "JCA_BEGIN_DELETE");
}

void Run() {
    auto context = androidlab::CreateCngKeymasterContext();
    Require(context->GetKmVersion() == KmVersion::KEYMASTER_4_1, "CONTEXT_VERSION");
    Record("reported_security_level_software", static_cast<PureSoftKeymasterContext*>(context.get())->GetSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE);
    Record("remote_provisioning_context_absent", context->GetRemoteProvisioningContext() == nullptr);
    Require(context->SetSystemVersion(140000, 202310) == KM_ERROR_OK, "SET_SYSTEM_VERSION");
    AndroidKeymaster device(context.release(), 8, kWireVersion);

    auto generated = Generate(device, Description());
    Error("generate_real_keymaster_request", generated->error, KM_ERROR_OK);
    Require(generated->error == KM_ERROR_OK, "GENERATION_REQUIRED");
    Record("opaque_blob_bounded", generated->key_blob.key_material_size >= 32 && generated->key_blob.key_material_size <= 64);
    Record("hardware_authorizations_empty", generated->enforced.empty());
    keymaster_algorithm_t algorithm = KM_ALGORITHM_AES;
    Record("software_rsa_authorization", generated->unenforced.GetTagValue(TAG_ALGORITHM, &algorithm) && algorithm == KM_ALGORITHM_RSA);
    auto characteristics = Characteristics(device, generated->key_blob);
    Error("load_current_context_reference", characteristics->error, KM_ERROR_OK);
    Record("loaded_authorizations_preserved", characteristics->error == KM_ERROR_OK
            && characteristics->enforced.empty() && SameAuthorizations(characteristics->unenforced, generated->unenforced));

    auto missing = Characteristics(device, generated->key_blob, AuthorizationSet{});
    Error("missing_application_binding", missing->error, KM_ERROR_INVALID_KEY_BLOB);
    AuthorizationSet wrong = Bindings();
    wrong.erase(wrong.find(KM_TAG_APPLICATION_ID));
    const uint8_t wrong_id[] = {0x61, 0x70, 0x70, 0x00, 0x32};
    wrong.push_back(TAG_APPLICATION_ID, wrong_id, sizeof(wrong_id));
    Error("wrong_application_binding", Characteristics(device, generated->key_blob, wrong)->error, KM_ERROR_INVALID_KEY_BLOB);
    AuthorizationSet duplicate = Bindings();
    duplicate.push_back(TAG_APPLICATION_ID, kAppId, sizeof(kAppId));
    Error("duplicate_application_binding", Characteristics(device, generated->key_blob, duplicate)->error, KM_ERROR_INVALID_KEY_BLOB);
    KeymasterKeyBlob altered(generated->key_blob);
    Require(altered.key_material_size > 0, "OPAQUE_BLOB_REQUIRED");
    altered.writable_data()[altered.key_material_size - 1] ^= 1;
    Error("altered_opaque_reference", Characteristics(device, altered)->error, KM_ERROR_INVALID_KEY_BLOB);

    auto exported = Export(device, generated->key_blob, KM_KEY_FORMAT_X509);
    Error("public_spki_export", exported->error, KM_ERROR_OK);
    Require(exported->error == KM_ERROR_OK, "PUBLIC_EXPORT_REQUIRED");
    Rejected("private_pkcs8_export_rejected", Export(device, generated->key_blob, KM_KEY_FORMAT_PKCS8)->error);
    const std::vector<uint8_t> payload{'a','n','d','r','o','i','d',0,'k','e','y','m','i','n','t',0xff,0x01};
    auto begin = Begin(device, generated->key_blob);
    Error("begin_pss_sha256", begin->error, KM_ERROR_OK);
    Require(begin->error == KM_ERROR_OK, "BEGIN_REQUIRED");
    UpdateOperationRequest update(kWireVersion);
    update.op_handle = begin->op_handle;
    Require(update.input.Reinitialize(payload.data(), 7), "UPDATE_INPUT_ALLOCATION");
    auto updated = Call(device, &AndroidKeymaster::UpdateOperation, update);
    Error("stream_update", updated->error, KM_ERROR_OK);
    Record("stream_input_consumed", updated->input_consumed == 7 && updated->output.available_read() == 0);
    auto finished = Finish(device, begin->op_handle, payload.data() + 7, payload.size() - 7);
    Error("finish_pss_signature", finished->error, KM_ERROR_OK);
    Require(finished->error == KM_ERROR_OK, "SIGNATURE_REQUIRED");
    std::vector<uint8_t> signature(finished->output.peek_read(), finished->output.peek_read() + finished->output.available_read());
    Record("independent_boringssl_signature", signature.size() == 256 && Verify(exported->key_data, exported->key_data_length, payload, signature));
    std::vector<uint8_t> changed_payload = payload;
    changed_payload.back() ^= 1;
    Record("independent_changed_message_rejected", !Verify(exported->key_data, exported->key_data_length, changed_payload, signature));
    std::vector<uint8_t> changed_signature = signature;
    changed_signature.back() ^= 1;
    Record("independent_changed_signature_rejected", !Verify(exported->key_data, exported->key_data_length, payload, changed_signature));
    Error("finish_consumes_operation_handle", Finish(device, begin->op_handle)->error, KM_ERROR_INVALID_OPERATION_HANDLE);
    Rejected("begin_wrong_digest", Begin(device, generated->key_blob, KM_DIGEST_SHA_2_512)->error);
    Rejected("begin_wrong_padding", Begin(device, generated->key_blob, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PKCS1_1_5_SIGN)->error);
    Rejected("begin_wrong_purpose", Begin(device, generated->key_blob, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS, KM_PURPOSE_ENCRYPT)->error);

    auto aborted = Begin(device, generated->key_blob);
    Require(aborted->error == KM_ERROR_OK, "ABORT_BEGIN_REQUIRED");
    AbortOperationRequest abort_request(kWireVersion);
    abort_request.op_handle = aborted->op_handle;
    Error("abort_active_operation", Call(device, &AndroidKeymaster::AbortOperation, abort_request)->error, KM_ERROR_OK);
    Error("abort_consumes_operation_handle", Finish(device, aborted->op_handle)->error, KM_ERROR_INVALID_OPERATION_HANDLE);
    auto active = Begin(device, generated->key_blob);
    Require(active->error == KM_ERROR_OK, "DELETE_BEGIN_REQUIRED");
    Error("delete_opaque_key", Delete(device, generated->key_blob)->error, KM_ERROR_OK);
    Error("load_after_delete", Characteristics(device, generated->key_blob)->error, KM_ERROR_INVALID_KEY_BLOB);
    Error("begin_after_delete", Begin(device, generated->key_blob)->error, KM_ERROR_INVALID_KEY_BLOB);
    Rejected("active_sign_after_key_delete", Finish(device, active->op_handle)->error);

    auto remaining = Generate(device, Description());
    Require(remaining->error == KM_ERROR_OK, "SECOND_KEY_REQUIRED");
    {
        auto other_context = androidlab::CreateCngKeymasterContext();
        Require(other_context->SetSystemVersion(140000, 202310) == KM_ERROR_OK, "SECOND_CONTEXT_VERSION");
        AndroidKeymaster other(other_context.release(), 8, kWireVersion);
        Error("cross_context_reference_rejected", Characteristics(other, remaining->key_blob)->error, KM_ERROR_INVALID_KEY_BLOB);
    }
    DeleteAllKeysRequest delete_all(kWireVersion);
    Error("delete_all_context_keys", Call(device, &AndroidKeymaster::DeleteAllKeys, delete_all)->error, KM_ERROR_OK);
    Error("load_after_delete_all", Characteristics(device, remaining->key_blob)->error, KM_ERROR_INVALID_KEY_BLOB);

    AuthorizationSet invalid = Description();
    invalid.push_back(TAG_USER_SECURE_ID, uint64_t{7});
    Rejected("unsupported_user_auth_generation", Generate(device, invalid)->error);
    invalid = Description(); invalid.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_512);
    Rejected("duplicate_digest_generation", Generate(device, invalid)->error);
    invalid = Description(); invalid.push_back(TAG_ROLLBACK_RESISTANCE);
    Rejected("unsupported_rollback_generation", Generate(device, invalid)->error);

    GenerateCsrRequest csr(kWireVersion);
    Rejected("remote_provisioning_csr_rejected", Call(device, &AndroidKeymaster::GenerateCsr, csr)->error);
    GenerateCsrV2Request csr_v2(kWireVersion);
    Rejected("remote_provisioning_csr_v2_rejected", Call(device, &AndroidKeymaster::GenerateCsrV2, csr_v2)->error);
    auto hardware_info = device.GetHwInfo();
    GetHwInfoResponse hardware_info_wire(kWireVersion);
    WireCopy(hardware_info, &hardware_info_wire);
    Rejected("remote_provisioning_info_rejected", hardware_info_wire.error);

    auto epoch_key = Generate(device, Description());
    Require(epoch_key->error == KM_ERROR_OK, "EPOCH_KEY_REQUIRED");
    UpgradeKeyRequest upgrade(kWireVersion);
    upgrade.SetKeyMaterial(epoch_key->key_blob);
    upgrade.upgrade_params = Bindings();
    auto current_upgrade = Call(device, &AndroidKeymaster::UpgradeKey, upgrade);
    Error("current_epoch_upgrade", current_upgrade->error, KM_ERROR_OK);
    ConfigureRequest configuration(kWireVersion);
    configuration.os_version = 140000;
    configuration.os_patchlevel = 202311;
    Error("configure_new_software_epoch", Call(device, &AndroidKeymaster::Configure, configuration)->error, KM_ERROR_OK);
    Error("old_epoch_requires_upgrade", Characteristics(device, epoch_key->key_blob)->error, KM_ERROR_KEY_REQUIRES_UPGRADE);
    Error("old_epoch_upgrade_does_not_rewrite_metadata", Call(device, &AndroidKeymaster::UpgradeKey, upgrade)->error, KM_ERROR_KEY_REQUIRES_UPGRADE);
    Error("delete_old_epoch_key", Delete(device, epoch_key->key_blob)->error, KM_ERROR_OK);

    GenerateKeyRequest framed(kWireVersion);
    framed.key_description = Description();
    std::vector<uint8_t> bytes(framed.SerializedSize());
    Require(framed.Serialize(bytes.data(), bytes.data() + bytes.size()) == bytes.data() + bytes.size(), "FRAME_SERIALIZATION");
    GenerateKeyRequest truncated(kWireVersion);
    const uint8_t* cursor = bytes.data();
    Record("truncated_request_rejected", !truncated.Deserialize(&cursor, bytes.data() + bytes.size() - 1));
}
}  // namespace

int main() {
    bool aborted = false;
    try { Run(); RunHalCompatibilityControls(); RunJcaBeginControls(); }
    catch (const std::exception& error) { aborted = true; std::cerr << error.what() << '\n'; }
    const size_t failed = std::count_if(results.begin(), results.end(), [](const Result& item) { return !item.passed; });
    std::cout << "{\"schema_version\":1,\"context\":\"native_android_keymaster_cng\",\"km_version\":\"4.1\","
              << "\"advertised_security_level\":\"SOFTWARE\",\"aborted\":" << (aborted ? "true" : "false")
              << ",\"passed\":" << results.size() - failed << ",\"failed\":" << failed
              << ",\"wire_round_trips\":" << wire_calls
              << ",\"auxiliary_authentication_tokens_validated\":false,\"provider_release_failure_fault_injected\":false"
              << ",\"android_guest_integrated\":false,\"android_tee_verified\":false,\"google_attestation_verified\":false,"
              << "\"zero_detections_achieved\":false,\"cases\":[";
    for (size_t index = 0; index < results.size(); ++index) {
        const auto& item = results[index];
        if (index) std::cout << ',';
        std::cout << "{\"name\":\"" << item.name << "\",\"passed\":" << (item.passed ? "true" : "false")
                  << ",\"actual\":" << item.actual << ",\"comparison\":\"" << (item.nonzero ? "nonzero" : "equal")
                  << "\",\"expected\":";
        if (item.nonzero) std::cout << "null"; else std::cout << item.expected;
        std::cout << '}';
    }
    std::cout << "]}\n";
    return aborted || failed ? 1 : 0;
}
