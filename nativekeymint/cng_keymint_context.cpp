#include "cng_keymint_context.h"
#include "cng_certificate.h"
#include "cng_key_store.h"
#include "lab_software_attestation.h"

#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/key.h>
#include <keymaster/key_factory.h>
#include <keymaster/keymaster_tags.h>
#include <keymaster/operation.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace androidlab {
namespace {

using namespace keymaster;
using KeyId = CngKeyStore::KeyId;
constexpr std::array<uint8_t, 4> kBlobVersion{{1, 0, 0, 0}};
constexpr size_t kBlobBytes = kBlobVersion.size() + KeyId{}.size();

struct Bindings {
  std::optional<std::vector<uint8_t>> application_id;
  std::optional<std::vector<uint8_t>> application_data;
};

keymaster_error_t ReadBindings(const AuthorizationSet& params, Bindings* bindings) {
  if (params.is_valid() != AuthorizationSet::OK) return KM_ERROR_INVALID_ARGUMENT;
  std::set<keymaster_tag_t> seen;
  for (const auto& entry : params) {
    std::optional<std::vector<uint8_t>>* value = nullptr;
    if (entry.tag == KM_TAG_APPLICATION_ID) value = &bindings->application_id;
    if (entry.tag == KM_TAG_APPLICATION_DATA) value = &bindings->application_data;
    if (!value) continue;
    if (!seen.insert(entry.tag).second) return KM_ERROR_INVALID_TAG;
    if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
    // The AIDL HAL omits empty application bindings when loading a key.
    if (!entry.blob.data_length) continue;
    value->emplace();
    value->value().assign(entry.blob.data, entry.blob.data + entry.blob.data_length);
  }
  return KM_ERROR_OK;
}

bool SameBindings(const Bindings& left, const Bindings& right) {
  return left.application_id == right.application_id &&
         left.application_data == right.application_data;
}

bool ReadId(const KeymasterKeyBlob& blob, KeyId* id) {
  if (blob.size() != kBlobBytes || !blob.begin() ||
      !std::equal(kBlobVersion.begin(), kBlobVersion.end(), blob.begin())) return false;
  std::copy(blob.begin() + kBlobVersion.size(), blob.end(), id->begin());
  return true;
}

KeymasterKeyBlob MakeBlob(const KeyId& id) {
  KeymasterKeyBlob blob(kBlobBytes);
  if (blob.size() != kBlobBytes) return blob;
  std::copy(kBlobVersion.begin(), kBlobVersion.end(), blob.writable_data());
  std::copy(id.begin(), id.end(), blob.writable_data() + kBlobVersion.size());
  return blob;
}

uint32_t ReadLe32(const uint8_t* value) {
  return uint32_t(value[0]) | (uint32_t(value[1]) << 8) |
         (uint32_t(value[2]) << 16) | (uint32_t(value[3]) << 24);
}

std::vector<uint8_t> PublicSpki(const std::vector<uint8_t>& blob) {
  // CNG's header is little endian; exponent and modulus are unsigned big endian.
  if (blob.size() != 24 + 3 + 256 || ReadLe32(blob.data()) != 0x31415352 ||
      ReadLe32(blob.data() + 4) != 2048 || ReadLe32(blob.data() + 8) != 3 ||
      ReadLe32(blob.data() + 12) != 256 || ReadLe32(blob.data() + 16) != 0 ||
      ReadLe32(blob.data() + 20) != 0 || blob[24] != 1 || blob[25] != 0 || blob[26] != 1)
    throw std::runtime_error("CNG_PUBLIC_BLOB_INVALID");
  bssl::UniquePtr<BIGNUM> exponent(BN_bin2bn(blob.data() + 24, 3, nullptr));
  bssl::UniquePtr<BIGNUM> modulus(BN_bin2bn(blob.data() + 27, 256, nullptr));
  bssl::UniquePtr<RSA> rsa(RSA_new());
  bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
  if (!exponent || !modulus || !rsa || !key) throw std::bad_alloc();
  if (BN_num_bits(modulus.get()) != 2048 ||
      RSA_set0_key(rsa.get(), modulus.get(), exponent.get(), nullptr) != 1)
    throw std::runtime_error("CNG_PUBLIC_PARAMETERS_INVALID");
  modulus.release();
  exponent.release();
  if (EVP_PKEY_set1_RSA(key.get(), rsa.get()) != 1)
    throw std::runtime_error("CNG_PUBLIC_KEY_INVALID");
  const int bytes = i2d_PUBKEY(key.get(), nullptr);
  if (bytes <= 0 || bytes > 1024) throw std::runtime_error("CNG_SPKI_SIZE_INVALID");
  std::vector<uint8_t> spki(static_cast<size_t>(bytes));
  uint8_t* cursor = spki.data();
  if (i2d_PUBKEY(key.get(), &cursor) != bytes || cursor != spki.data() + spki.size())
    throw std::runtime_error("CNG_SPKI_ENCODING_FAILED");
  return spki;
}

struct Record {
  AuthorizationSet software;
  Bindings bindings;
  std::vector<uint8_t> public_spki;
  uint32_t os_version;
  uint32_t os_patchlevel;
  std::optional<uint32_t> vendor_patchlevel;
  std::optional<uint32_t> boot_patchlevel;
};

struct State {
  // This lock spans lookup and CNG calls, so Delete cannot race a successful Sign.
  std::mutex mutex;
  CngKeyStore store;
  std::map<KeyId, Record> records;
};

keymaster_error_t VersionStatus(const Record& record, const KeymasterContext& context) {
  uint32_t version = 0, patchlevel = 0;
  context.GetSystemVersion(&version, &patchlevel);
  if (record.os_version > version || record.os_patchlevel > patchlevel)
    return KM_ERROR_INVALID_KEY_BLOB;
  if (record.os_version < version || record.os_patchlevel < patchlevel)
    return KM_ERROR_KEY_REQUIRES_UPGRADE;
  const auto check_patch = [](std::optional<uint32_t> saved, std::optional<uint32_t> current) {
    if (saved == current) return KM_ERROR_OK;
    if (!current || (saved && *saved > *current)) return KM_ERROR_INVALID_KEY_BLOB;
    return KM_ERROR_KEY_REQUIRES_UPGRADE;
  };
  auto error = check_patch(record.vendor_patchlevel, context.GetVendorPatchlevel());
  if (error != KM_ERROR_OK) return error;
  error = check_patch(record.boot_patchlevel, context.GetBootPatchlevel());
  if (error != KM_ERROR_OK) return error;
  return KM_ERROR_OK;
}

bool IsCertificateTag(keymaster_tag_t tag) {
  return tag == KM_TAG_CERTIFICATE_SERIAL || tag == KM_TAG_CERTIFICATE_SUBJECT ||
         tag == KM_TAG_CERTIFICATE_NOT_BEFORE || tag == KM_TAG_CERTIFICATE_NOT_AFTER;
}

keymaster_error_t ValidateDescription(const AuthorizationSet& params, KmVersion version,
    bool lab_attestation) {
  if (params.is_valid() != AuthorizationSet::OK) return KM_ERROR_INVALID_ARGUMENT;
  std::set<keymaster_tag_t> seen;
  for (const auto& entry : params) {
    if (!seen.insert(entry.tag).second) return KM_ERROR_INVALID_TAG;
    switch (entry.tag) {
      case KM_TAG_ALGORITHM:
        if (entry.enumerated != KM_ALGORITHM_RSA) return KM_ERROR_UNSUPPORTED_ALGORITHM;
        break;
      case KM_TAG_KEY_SIZE:
        if (entry.integer != 2048) return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        break;
      case KM_TAG_PURPOSE:
        if (entry.enumerated != KM_PURPOSE_SIGN) return KM_ERROR_UNSUPPORTED_PURPOSE;
        break;
      case KM_TAG_DIGEST:
        if (entry.enumerated != KM_DIGEST_SHA_2_256) return KM_ERROR_UNSUPPORTED_DIGEST;
        break;
      case KM_TAG_PADDING:
        if (entry.enumerated != KM_PAD_RSA_PSS) return KM_ERROR_UNSUPPORTED_PADDING_MODE;
        break;
      case KM_TAG_RSA_PUBLIC_EXPONENT:
        if (entry.long_integer != 65537) return KM_ERROR_INVALID_ARGUMENT;
        break;
      case KM_TAG_NO_AUTH_REQUIRED:
        if (!entry.boolean) return KM_ERROR_INVALID_TAG;
        break;
      case KM_TAG_CREATION_DATETIME:
        if (entry.date_time > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
          return KM_ERROR_INVALID_ARGUMENT;
        break;
      case KM_TAG_APPLICATION_ID:
      case KM_TAG_APPLICATION_DATA:
        if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
        break;
      case KM_TAG_CERTIFICATE_SERIAL:
      case KM_TAG_CERTIFICATE_SUBJECT:
        if (version != KmVersion::KEYMINT_3) return KM_ERROR_UNSUPPORTED_TAG;
        if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
        break;
      case KM_TAG_CERTIFICATE_NOT_BEFORE:
      case KM_TAG_CERTIFICATE_NOT_AFTER:
        if (version != KmVersion::KEYMINT_3) return KM_ERROR_UNSUPPORTED_TAG;
        break;
      case KM_TAG_ATTESTATION_CHALLENGE:
      case KM_TAG_ATTESTATION_APPLICATION_ID:
        if (!lab_attestation) return entry.tag == KM_TAG_ATTESTATION_CHALLENGE ?
            KM_ERROR_UNIMPLEMENTED : KM_ERROR_UNSUPPORTED_TAG;
        if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
        break;
      case KM_TAG_INCLUDE_UNIQUE_ID:
      case KM_TAG_DEVICE_UNIQUE_ATTESTATION:
      case KM_TAG_RESET_SINCE_ID_ROTATION:
        return KM_ERROR_UNIMPLEMENTED;
      default:
        if (keymaster_tag_mask_type(entry.tag) == keymaster_tag_mask_type(KM_TAG_CREATION_DATETIME))
          return KM_ERROR_INVALID_TAG;
        return KM_ERROR_UNSUPPORTED_TAG;
    }
  }
  for (const auto tag : {KM_TAG_ALGORITHM, KM_TAG_KEY_SIZE, KM_TAG_PURPOSE,
                         KM_TAG_DIGEST, KM_TAG_PADDING, KM_TAG_RSA_PUBLIC_EXPONENT,
                         KM_TAG_NO_AUTH_REQUIRED}) {
    if (seen.count(tag) != 1) return KM_ERROR_INVALID_ARGUMENT;
  }
  if (version == KmVersion::KEYMINT_3) {
    if (seen.count(KM_TAG_CERTIFICATE_NOT_BEFORE) != 1) return KM_ERROR_MISSING_NOT_BEFORE;
    if (seen.count(KM_TAG_CERTIFICATE_NOT_AFTER) != 1) return KM_ERROR_MISSING_NOT_AFTER;
  }
  return KM_ERROR_OK;
}

keymaster_error_t ValidateBegin(const AuthorizationSet& params) {
  if (params.is_valid() != AuthorizationSet::OK) return KM_ERROR_INVALID_ARGUMENT;
  std::set<keymaster_tag_t> seen;
  for (const auto& entry : params) {
    if (!seen.insert(entry.tag).second) return KM_ERROR_INVALID_TAG;
    switch (entry.tag) {
      case KM_TAG_ALGORITHM:
        if (entry.enumerated != KM_ALGORITHM_RSA) return KM_ERROR_INCOMPATIBLE_ALGORITHM;
        break;
      case KM_TAG_DIGEST:
      case KM_TAG_PADDING:
        break;
      case KM_TAG_APPLICATION_ID:
      case KM_TAG_APPLICATION_DATA:
      case KM_TAG_AUTH_TOKEN:
        if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
        break;
      default:
        if (keymaster_tag_mask_type(entry.tag) == keymaster_tag_mask_type(KM_TAG_ALGORITHM))
          return KM_ERROR_INVALID_TAG;
        return KM_ERROR_UNSUPPORTED_TAG;
    }
  }
  return KM_ERROR_OK;
}

keymaster_error_t ValidateOperationParameters(const AuthorizationSet& params) {
  if (params.is_valid() != AuthorizationSet::OK) return KM_ERROR_INVALID_ARGUMENT;
  bool token_seen = false;
  for (const auto& entry : params) {
    if (entry.tag != KM_TAG_AUTH_TOKEN) return KM_ERROR_UNSUPPORTED_TAG;
    if (token_seen) return KM_ERROR_INVALID_TAG;
    token_seen = true;
    if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
  }
  // Every CNG key requires NO_AUTH_REQUIRED. The HAL's optional token is
  // transport metadata here; accepting it does not validate authentication.
  return KM_ERROR_OK;
}

class CngKey final : public Key {
 public:
  CngKey(std::shared_ptr<State> state, const KeyId& id, AuthorizationSet&& software,
         const KeyFactory* factory)
      : Key(AuthorizationSet{}, std::move(software), factory), state_(std::move(state)), id_(id) {
    key_material_ = MakeBlob(id);
  }

  keymaster_error_t formatted_key_material(keymaster_key_format_t format,
      UniquePtr<uint8_t[]>* material, size_t* size) const override {
    if (!material || !size) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    material->reset();
    *size = 0;
    if (format != KM_KEY_FORMAT_X509) return KM_ERROR_UNSUPPORTED_KEY_FORMAT;
    try {
      std::lock_guard<std::mutex> lock(state_->mutex);
      const auto found = state_->records.find(id_);
      if (found == state_->records.end()) return KM_ERROR_INVALID_KEY_BLOB;
      const auto& spki = found->second.public_spki;
      UniquePtr<uint8_t[]> output(new (std::nothrow) uint8_t[spki.size()]);
      if (!output) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      std::copy(spki.begin(), spki.end(), output.get());
      *size = spki.size();
      *material = std::move(output);
      return KM_ERROR_OK;
    } catch (const std::bad_alloc&) { return KM_ERROR_MEMORY_ALLOCATION_FAILED; }
      catch (...) { return KM_ERROR_UNKNOWN_ERROR; }
  }

  const std::shared_ptr<State>& state() const { return state_; }
  const KeyId& id() const { return id_; }

 private:
  std::shared_ptr<State> state_;
  KeyId id_;
};

class CngSignOperation final : public Operation {
 public:
  explicit CngSignOperation(CngKey& key)
      : Operation(KM_PURPOSE_SIGN, key.hw_enforced_move(), key.sw_enforced_move()),
        state_(key.state()), id_(key.id()) { operation_handle_ = 0; }

  keymaster_error_t Begin(const AuthorizationSet&, AuthorizationSet* output_params) override {
    if (!output_params) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    output_params->Clear();
    if (active_) return KM_ERROR_INVALID_OPERATION_HANDLE;
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->records.count(id_) != 1) return KM_ERROR_INVALID_KEY_BLOB;
    do {
      if (RAND_bytes(reinterpret_cast<uint8_t*>(&operation_handle_), sizeof(operation_handle_)) != 1)
        return KM_ERROR_UNKNOWN_ERROR;
    } while (operation_handle_ == 0);
    if (SHA256_Init(&digest_) != 1) return KM_ERROR_UNKNOWN_ERROR;
    active_ = true;
    return KM_ERROR_OK;
  }

  keymaster_error_t Update(const AuthorizationSet& input_params, const Buffer& input,
      AuthorizationSet* output_params, Buffer* output, size_t* input_consumed) override {
    if (!input_consumed || !output_params || !output) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    *input_consumed = 0;
    output_params->Clear();
    output->Clear();
    if (!active_) return KM_ERROR_INVALID_OPERATION_HANDLE;
    const auto error = ValidateOperationParameters(input_params);
    if (error != KM_ERROR_OK) return error;
    if (!input.valid_buffer_state()) return KM_ERROR_INVALID_ARGUMENT;
    {
      std::lock_guard<std::mutex> lock(state_->mutex);
      if (state_->records.count(id_) != 1) return KM_ERROR_INVALID_KEY_BLOB;
    }
    const size_t bytes = input.available_read();
    if (bytes && SHA256_Update(&digest_, input.peek_read(), bytes) != 1)
      return KM_ERROR_UNKNOWN_ERROR;
    *input_consumed = bytes;
    return KM_ERROR_OK;
  }

  keymaster_error_t Finish(const AuthorizationSet& input_params, const Buffer& input,
      const Buffer& signature, AuthorizationSet* output_params, Buffer* output) override {
    if (!output_params || !output) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    output_params->Clear();
    output->Clear();
    if (!active_) return KM_ERROR_INVALID_OPERATION_HANDLE;
    active_ = false;
    const auto error = ValidateOperationParameters(input_params);
    if (error != KM_ERROR_OK) return error;
    if (!input.valid_buffer_state() || !signature.valid_buffer_state())
      return KM_ERROR_INVALID_ARGUMENT;
    if (signature.available_read() != 0) return KM_ERROR_INVALID_ARGUMENT;
    if (input.available_read() && SHA256_Update(&digest_, input.peek_read(), input.available_read()) != 1)
      return KM_ERROR_UNKNOWN_ERROR;
    std::array<uint8_t, 32> digest{};
    if (SHA256_Final(digest.data(), &digest_) != 1) return KM_ERROR_UNKNOWN_ERROR;
    try {
      std::lock_guard<std::mutex> lock(state_->mutex);
      if (state_->records.count(id_) != 1) return KM_ERROR_INVALID_KEY_BLOB;
      const auto bytes = state_->store.SignSha256(id_, digest);
      if (bytes.size() != 256) return KM_ERROR_UNKNOWN_ERROR;
      if (!output->Reinitialize(bytes.data(), bytes.size())) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      return KM_ERROR_OK;
    } catch (const std::bad_alloc&) { return KM_ERROR_MEMORY_ALLOCATION_FAILED; }
      catch (...) { return KM_ERROR_UNKNOWN_ERROR; }
  }

  keymaster_error_t Abort() override {
    active_ = false;
    operation_handle_ = 0;
    std::memset(&digest_, 0, sizeof(digest_));
    return KM_ERROR_OK;
  }

 private:
  std::shared_ptr<State> state_;
  KeyId id_;
  SHA256_CTX digest_{};
  bool active_ = false;
};

class CngOperationFactory final : public OperationFactory {
 public:
  explicit CngOperationFactory(const KeyFactory* owner) : owner_(owner) {}
  KeyType registry_key() const override { return {KM_ALGORITHM_RSA, KM_PURPOSE_SIGN}; }

  OperationPtr CreateOperation(Key&& key, const AuthorizationSet& params,
                              keymaster_error_t* error) override {
    if (!error) return {};
    try {
      *error = ValidateBegin(params);
      if (*error != KM_ERROR_OK) return {};
      if (key.key_factory() != owner_) { *error = KM_ERROR_INVALID_KEY_BLOB; return {}; }
      keymaster_digest_t digest;
      keymaster_padding_t padding;
      if (!GetAndValidateDigest(params, key, &digest, error, true) ||
          !GetAndValidatePadding(params, key, &padding, error)) return {};
      OperationPtr operation(new (std::nothrow) CngSignOperation(static_cast<CngKey&>(key)));
      *error = operation ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
      return operation;
    } catch (const std::bad_alloc&) { *error = KM_ERROR_MEMORY_ALLOCATION_FAILED; }
      catch (...) { *error = KM_ERROR_UNKNOWN_ERROR; }
    return {};
  }

  const keymaster_padding_t* SupportedPaddingModes(size_t* count) const override {
    static constexpr keymaster_padding_t modes[] = {KM_PAD_RSA_PSS};
    *count = 1;
    return modes;
  }
  const keymaster_digest_t* SupportedDigests(size_t* count) const override {
    static constexpr keymaster_digest_t digests[] = {KM_DIGEST_SHA_2_256};
    *count = 1;
    return digests;
  }

 private:
  const KeyFactory* owner_;
};

class CngKeyFactory final : public KeyFactory {
 public:
  CngKeyFactory(const KeymasterContext& context, std::shared_ptr<State> state,
      std::shared_ptr<LabSoftwareAttestation> lab_attestation)
      : context_(context), state_(std::move(state)), lab_attestation_(std::move(lab_attestation)), operations_(this) {}

  keymaster_error_t GenerateKey(const AuthorizationSet& description, UniquePtr<Key> attest_key,
      const KeymasterBlob& issuer_subject, KeymasterKeyBlob* blob, AuthorizationSet* hardware,
      AuthorizationSet* software, CertificateChain* chain) const override {
    if (!blob || !hardware || !software) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    blob->Clear();
    hardware->Clear();
    software->Clear();
    if (chain) chain->Clear();
    if (attest_key || issuer_subject.size()) return KM_ERROR_UNIMPLEMENTED;
    const bool create_certificate = context_.GetKmVersion() == KmVersion::KEYMINT_3;
    if (create_certificate && !chain) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    try {
      auto error = ValidateDescription(description, context_.GetKmVersion(), lab_attestation_ != nullptr);
      if (error != KM_ERROR_OK) return error;
      if (lab_attestation_) {
        error = LabSoftwareAttestation::ValidateRequest(description, false);
        if (error != KM_ERROR_OK) return error;
      }
      Bindings bindings;
      error = ReadBindings(description, &bindings);
      if (error != KM_ERROR_OK) return error;
      Record record;
      record.bindings = std::move(bindings);
      context_.GetSystemVersion(&record.os_version, &record.os_patchlevel);
      record.vendor_patchlevel = context_.GetVendorPatchlevel();
      record.boot_patchlevel = context_.GetBootPatchlevel();
      for (const auto& entry : description) {
        if (entry.tag != KM_TAG_APPLICATION_ID && entry.tag != KM_TAG_APPLICATION_DATA &&
            entry.tag != KM_TAG_ATTESTATION_CHALLENGE && entry.tag != KM_TAG_ATTESTATION_APPLICATION_ID &&
            !IsCertificateTag(entry.tag) &&
            !record.software.push_back(entry)) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      }
      if (!record.software.push_back(TAG_ORIGIN, KM_ORIGIN_GENERATED) ||
          !record.software.push_back(TAG_OS_VERSION, record.os_version) ||
          !record.software.push_back(TAG_OS_PATCHLEVEL, record.os_patchlevel))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      if (record.vendor_patchlevel &&
          !record.software.push_back(TAG_VENDOR_PATCHLEVEL, *record.vendor_patchlevel))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      if (record.boot_patchlevel &&
          !record.software.push_back(TAG_BOOT_PATCHLEVEL, *record.boot_patchlevel))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      AuthorizationSet output_software(record.software);
      if (output_software.is_valid() != AuthorizationSet::OK) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      std::lock_guard<std::mutex> lock(state_->mutex);
      const KeyId id = state_->store.GenerateRsaPss2048();
      bool committed = false;
      auto cleanup = finally([&] {
        if (!committed) { try { state_->store.Delete(id); } catch (...) {} }
      });
      record.public_spki = PublicSpki(state_->store.PublicBlob(id));
      auto output_blob = MakeBlob(id);
      if (output_blob.size() != kBlobBytes) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      CertificateChain output_chain;
      if (create_certificate) {
        // CngKey is not an AOSP AsymmetricKey. The helper signs the public
        // certificate's TBS digest through CNG without accessing private material.
        if (lab_attestation_ && description.Contains(TAG_ATTESTATION_CHALLENGE)) {
          const uint8_t* cursor = record.public_spki.data();
          bssl::UniquePtr<EVP_PKEY> public_key(d2i_PUBKEY(nullptr, &cursor, record.public_spki.size()));
          if (!public_key || cursor != record.public_spki.data() + record.public_spki.size())
            return KM_ERROR_INVALID_KEY_BLOB;
          output_chain = lab_attestation_->Generate(public_key.get(), record.software,
              AuthorizationSet{}, description, &error);
        } else {
          output_chain = GenerateCngSelfSignedCertificate(state_->store, id, description, &error);
        }
        if (error != KM_ERROR_OK) return error;
        const size_t expected_count = lab_attestation_ && description.Contains(TAG_ATTESTATION_CHALLENGE) ? 2 : 1;
        if (output_chain.entry_count != expected_count || !output_chain.entries ||
            !output_chain.entries[0].data || output_chain.entries[0].data_length == 0)
          return KM_ERROR_UNKNOWN_ERROR;
      }
      if (!state_->records.emplace(id, std::move(record)).second) return KM_ERROR_UNKNOWN_ERROR;
      *blob = std::move(output_blob);
      *software = std::move(output_software);
      if (chain) *chain = std::move(output_chain);
      committed = true;
      return KM_ERROR_OK;
    } catch (const std::bad_alloc&) { return KM_ERROR_MEMORY_ALLOCATION_FAILED; }
      catch (...) { return KM_ERROR_UNKNOWN_ERROR; }
  }

  keymaster_error_t ImportKey(const AuthorizationSet&, keymaster_key_format_t,
      const KeymasterKeyBlob&, UniquePtr<Key>, const KeymasterBlob&, KeymasterKeyBlob*,
      AuthorizationSet*, AuthorizationSet*, CertificateChain*) const override {
    return KM_ERROR_UNSUPPORTED_KEY_FORMAT;
  }

  keymaster_error_t LoadKey(KeymasterKeyBlob&& blob, const AuthorizationSet& params,
      AuthorizationSet&&, AuthorizationSet&&, UniquePtr<Key>* key) const override {
    return Load(blob, params, key);
  }

  keymaster_error_t Load(const KeymasterKeyBlob& blob, const AuthorizationSet& params,
      UniquePtr<Key>* key) const {
    if (!key) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    key->reset();
    try {
      KeyId id{};
      if (!ReadId(blob, &id)) return KM_ERROR_INVALID_KEY_BLOB;
      Bindings bindings;
      const auto error = ReadBindings(params, &bindings);
      if (error != KM_ERROR_OK)
        return error == KM_ERROR_INVALID_TAG ? KM_ERROR_INVALID_KEY_BLOB : error;
      std::lock_guard<std::mutex> lock(state_->mutex);
      const auto found = state_->records.find(id);
      if (found == state_->records.end() || !SameBindings(found->second.bindings, bindings))
        return KM_ERROR_INVALID_KEY_BLOB;
      const auto version = VersionStatus(found->second, context_);
      if (version != KM_ERROR_OK) return version;
      AuthorizationSet software(found->second.software);
      if (software.is_valid() != AuthorizationSet::OK) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      UniquePtr<Key> loaded(new (std::nothrow) CngKey(state_, id, std::move(software), this));
      if (!loaded || loaded->key_material().size() != kBlobBytes) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
      *key = std::move(loaded);
      return KM_ERROR_OK;
    } catch (const std::bad_alloc&) { return KM_ERROR_MEMORY_ALLOCATION_FAILED; }
      catch (...) { return KM_ERROR_UNKNOWN_ERROR; }
  }

  OperationFactory* GetOperationFactory(keymaster_purpose_t purpose) const override {
    return purpose == KM_PURPOSE_SIGN ? &operations_ : nullptr;
  }
  const keymaster_key_format_t* SupportedImportFormats(size_t* count) const override {
    *count = 0;
    return nullptr;
  }
  const keymaster_key_format_t* SupportedExportFormats(size_t* count) const override {
    static constexpr keymaster_key_format_t formats[] = {KM_KEY_FORMAT_X509};
    *count = 1;
    return formats;
  }

 private:
  const KeymasterContext& context_;
  std::shared_ptr<State> state_;
  std::shared_ptr<LabSoftwareAttestation> lab_attestation_;
  mutable CngOperationFactory operations_;
};

KmVersion SupportedVersion(KmVersion version) {
  if (version != KmVersion::KEYMASTER_4_1 && version != KmVersion::KEYMINT_3)
    throw std::invalid_argument("CNG_KEYMASTER_VERSION_UNSUPPORTED");
  return version;
}

class CngKeymasterContext final : public PureSoftKeymasterContext {
 public:
  explicit CngKeymasterContext(KmVersion version, std::shared_ptr<LabSoftwareAttestation> lab_attestation)
      : PureSoftKeymasterContext(SupportedVersion(version), KM_SECURITY_LEVEL_SOFTWARE),
        state_(std::make_shared<State>()), lab_attestation_(std::move(lab_attestation)),
        factory_(*this, state_, lab_attestation_) {}
  ~CngKeymasterContext() override { DeleteAllKeys(); }

  KeyFactory* GetKeyFactory(keymaster_algorithm_t algorithm) const override {
    return algorithm == KM_ALGORITHM_RSA ? &factory_ : nullptr;
  }
  OperationFactory* GetOperationFactory(keymaster_algorithm_t algorithm,
      keymaster_purpose_t purpose) const override {
    return algorithm == KM_ALGORITHM_RSA ? factory_.GetOperationFactory(purpose) : nullptr;
  }
  const keymaster_algorithm_t* GetSupportedAlgorithms(size_t* count) const override {
    static constexpr keymaster_algorithm_t algorithms[] = {KM_ALGORITHM_RSA};
    *count = 1;
    return algorithms;
  }
  keymaster_error_t ParseKeyBlob(const KeymasterKeyBlob& blob,
      const AuthorizationSet& params, UniquePtr<Key>* key) const override {
    return factory_.Load(blob, params, key);
  }
  keymaster_error_t UpgradeKeyBlob(const KeymasterKeyBlob& blob,
      const AuthorizationSet& params, KeymasterKeyBlob* upgraded) const override {
    if (!upgraded) return KM_ERROR_OUTPUT_PARAMETER_NULL;
    upgraded->Clear();
    UniquePtr<Key> key;
    const auto error = factory_.Load(blob, params, &key);
    // No metadata rewrite can honestly upgrade this process-local key's creation epoch.
    if (error != KM_ERROR_OK) return error;
    if (!upgraded->Reset(blob.size())) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(blob.begin(), blob.end(), upgraded->writable_data());
    return KM_ERROR_OK;
  }
  keymaster_error_t DeleteKey(const KeymasterKeyBlob& blob) const override {
    KeyId id{};
    if (!ReadId(blob, &id)) return KM_ERROR_INVALID_KEY_BLOB;
    try {
      std::lock_guard<std::mutex> lock(state_->mutex);
      const auto found = state_->records.find(id);
      if (found == state_->records.end()) return KM_ERROR_INVALID_KEY_BLOB;
      if (!state_->store.Delete(id)) return KM_ERROR_INVALID_KEY_BLOB;
      state_->records.erase(found);
      return KM_ERROR_OK;
    } catch (...) { return KM_ERROR_UNKNOWN_ERROR; }
  }
  keymaster_error_t DeleteAllKeys() const override {
    try {
      std::lock_guard<std::mutex> lock(state_->mutex);
      keymaster_error_t result = KM_ERROR_OK;
      for (auto entry = state_->records.begin(); entry != state_->records.end();) {
        bool deleted = false;
        try { deleted = state_->store.Delete(entry->first); }
        catch (...) {}
        if (deleted) entry = state_->records.erase(entry);
        else { result = KM_ERROR_UNKNOWN_ERROR; ++entry; }
      }
      return result;
    } catch (...) { return KM_ERROR_UNKNOWN_ERROR; }
  }

  // An explicitly supplied laboratory CA can attest public keys. Fixture keys,
  // unique IDs, remote provisioning, and wrapped-key routes remain unsupported.
  CertificateChain GenerateAttestation(const Key& key, const AuthorizationSet& parameters, UniquePtr<Key> attest_key,
      const KeymasterBlob& issuer, keymaster_error_t* error) const override {
    if (lab_attestation_ && !attest_key && !issuer.size())
      return lab_attestation_->Generate(key, parameters, error);
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
  }
  CertificateChain GenerateSelfSignedCertificate(const Key&, const AuthorizationSet&, bool,
      keymaster_error_t* error) const override {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
  }
  Buffer GenerateUniqueId(uint64_t, const keymaster_blob_t&, bool,
      keymaster_error_t* error) const override {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
  }
  KeymasterKeyBlob GetAttestationKey(keymaster_algorithm_t,
      keymaster_error_t* error) const override {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
  }
  CertificateChain GetAttestationChain(keymaster_algorithm_t,
      keymaster_error_t* error) const override {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
  }
  const VerifiedBootParams* GetVerifiedBootParams(keymaster_error_t* error) const override {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return nullptr;
  }
  RemoteProvisioningContext* GetRemoteProvisioningContext() const override { return nullptr; }
  keymaster_error_t CreateKeyBlob(const AuthorizationSet&, keymaster_key_origin_t,
      const KeymasterKeyBlob&, KeymasterKeyBlob*, AuthorizationSet*, AuthorizationSet*) const override {
    return KM_ERROR_UNIMPLEMENTED;
  }
  keymaster_error_t UnwrapKey(const KeymasterKeyBlob&, const KeymasterKeyBlob&,
      const AuthorizationSet&, const KeymasterKeyBlob&, AuthorizationSet*,
      keymaster_key_format_t*, KeymasterKeyBlob*) const override {
    return KM_ERROR_UNSUPPORTED_KEY_FORMAT;
  }

 private:
  std::shared_ptr<State> state_;
  std::shared_ptr<LabSoftwareAttestation> lab_attestation_;
  mutable CngKeyFactory factory_;
};

}  // namespace

std::unique_ptr<keymaster::KeymasterContext> CreateCngKeymasterContext(KmVersion version,
    std::shared_ptr<LabSoftwareAttestation> lab_attestation) {
  if (lab_attestation && version != KmVersion::KEYMINT_3)
    throw std::invalid_argument("LAB_ATTESTATION_REQUIRES_KEYMINT3");
  return std::make_unique<CngKeymasterContext>(version, std::move(lab_attestation));
}

}  // namespace androidlab
