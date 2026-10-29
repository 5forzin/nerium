#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/keymaster_tags.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

using namespace keymaster;

namespace {
size_t message_count = 0;
size_t wire_bytes = 0;

void Require(bool condition, const char* stage) {
    if (!condition) throw std::runtime_error(stage);
}

template<class Message>
void RoundTrip(const Message& input, Message& output) {
    const size_t size = input.SerializedSize();
    Require(size <= 1024 * 1024, "message size");
    std::vector<uint8_t> wire(size);
    Require(input.Serialize(wire.data(), wire.data() + size) == wire.data() + size,
            "message serialization");
    const uint8_t* cursor = wire.data();
    Require(output.Deserialize(&cursor, wire.data() + size) && cursor == wire.data() + size,
            "message deserialization");
    ++message_count;
    wire_bytes += size;
}

template<class Request, class Response>
void Exchange(AndroidKeymaster& engine, const Request& request, Response& response,
              void (AndroidKeymaster::*method)(const Request&, Response*)) {
    Request decoded(engine.message_version());
    RoundTrip(request, decoded);
    Response generated(engine.message_version());
    (engine.*method)(decoded, &generated);
    RoundTrip(generated, response);
}

keymaster_operation_handle_t Begin(AndroidKeymaster& engine, const KeymasterKeyBlob& blob,
                                  keymaster_purpose_t purpose) {
    BeginOperationRequest request(engine.message_version());
    request.purpose = purpose;
    request.SetKeyMaterial(blob);
    request.additional_params.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    request.additional_params.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
    BeginOperationResponse response(engine.message_version());
    Exchange(engine, request, response, &AndroidKeymaster::BeginOperation);
    Require(response.error == KM_ERROR_OK, "begin");
    return response.op_handle;
}

void Update(AndroidKeymaster& engine, keymaster_operation_handle_t handle,
            const uint8_t* input, size_t length) {
    UpdateOperationRequest request(engine.message_version());
    request.op_handle = handle;
    Require(request.input.Reinitialize(input, length), "update input");
    UpdateOperationResponse response(engine.message_version());
    Exchange(engine, request, response, &AndroidKeymaster::UpdateOperation);
    Require(response.error == KM_ERROR_OK && response.input_consumed == length, "update");
}
}

int main() {
    try {
        AndroidKeymaster engine(new PureSoftKeymasterContext(KmVersion::KEYMASTER_4_1,
                                                            KM_SECURITY_LEVEL_SOFTWARE), 16);
        const int version = engine.message_version();
        GenerateKeyRequest create(version);
        create.key_description.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        create.key_description.push_back(TAG_KEY_SIZE, 2048);
        create.key_description.push_back(TAG_RSA_PUBLIC_EXPONENT, uint64_t(65537));
        create.key_description.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
        create.key_description.push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
        create.key_description.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        create.key_description.push_back(TAG_PADDING, KM_PAD_RSA_PSS);
        create.key_description.push_back(TAG_NO_AUTH_REQUIRED);
        GenerateKeyResponse key(version);
        Exchange(engine, create, key, &AndroidKeymaster::GenerateKey);
        Require(key.error == KM_ERROR_OK && key.key_blob.key_material_size > 0, "generate");
        Require(key.enforced.empty(), "software authorization classification");
        Require(key.certificate_chain.entry_count == 0, "no certificates");

        static const uint8_t message[] = "AndroidKeymaster native Windows baseline";
        const auto handle = Begin(engine, key.key_blob, KM_PURPOSE_SIGN);
        Update(engine, handle, message, 11);
        Update(engine, handle, message + 11, sizeof(message) - 1 - 11);
        FinishOperationRequest finish(version);
        finish.op_handle = handle;
        FinishOperationResponse signature(version);
        Exchange(engine, finish, signature, &AndroidKeymaster::FinishOperation);
        Require(signature.error == KM_ERROR_OK && signature.output.available_read() == 256,
                "finish signature");

        ExportKeyRequest export_request(version);
        export_request.SetKeyMaterial(key.key_blob);
        export_request.key_format = KM_KEY_FORMAT_X509;
        ExportKeyResponse public_key(version);
        Exchange(engine, export_request, public_key, &AndroidKeymaster::ExportKey);
        Require(public_key.error == KM_ERROR_OK, "public export");
        const uint8_t* public_cursor = public_key.key_data;
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> verifier(
            d2i_PUBKEY(nullptr, &public_cursor, public_key.key_data_length), EVP_PKEY_free);
        Require(verifier != nullptr, "public decode");
        auto verify = [&](const uint8_t* data, size_t length) {
            std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            EVP_PKEY_CTX* pctx = nullptr;
            Require(EVP_DigestVerifyInit(md.get(), &pctx, EVP_sha256(), nullptr, verifier.get()) == 1,
                    "verify init");
            Require(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) == 1, "verify PSS");
            return EVP_DigestVerify(md.get(), signature.output.peek_read(),
                                    signature.output.available_read(), data, length) == 1;
        };
        Require(verify(message, sizeof(message) - 1), "public verify");
        std::vector<uint8_t> altered(message, message + sizeof(message) - 1);
        altered[0] ^= 1;
        Require(!verify(altered.data(), altered.size()), "altered message rejection");

        FinishOperationResponse reused(version);
        Exchange(engine, finish, reused, &AndroidKeymaster::FinishOperation);
        Require(reused.error == KM_ERROR_INVALID_OPERATION_HANDLE, "finished handle rejection");
        const auto abort_handle = Begin(engine, key.key_blob, KM_PURPOSE_SIGN);
        AbortOperationRequest abort(version);
        abort.op_handle = abort_handle;
        AbortOperationResponse aborted(version);
        Exchange(engine, abort, aborted, &AndroidKeymaster::AbortOperation);
        Require(aborted.error == KM_ERROR_OK, "abort");
        std::printf("{\"schema_version\":1,\"backend\":\"aosp_software\","
                    "\"security_level\":\"SOFTWARE\",\"algorithm\":\"RSA_PSS_2048_SHA256\","
                    "\"generate_begin_update_finish\":true,\"public_verify\":true,"
                    "\"altered_message_rejected\":true,\"finished_handle_rejected\":true,"
                    "\"abort\":true,\"certificate_count\":0,\"serialized_messages\":%zu,"
                    "\"wire_bytes\":%zu,\"key_blob_bytes\":%zu,\"signature_bytes\":256}\n",
                    message_count, wire_bytes, key.key_blob.key_material_size);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Native Keymaster baseline failed: %s\n", error.what());
        return 1;
    }
}
