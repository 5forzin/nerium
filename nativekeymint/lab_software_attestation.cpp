#include "lab_software_attestation.h"

#include <keymaster/key.h>
#include <keymaster/keymaster_tags.h>
#include <keymaster/km_openssl/attestation_utils.h>
#include <keymaster/km_openssl/certificate_utils.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <mutex>
#include <new>
#include <set>
#include <stdexcept>
#include <vector>

namespace androidlab {
namespace {
using namespace keymaster;
constexpr uint64_t kMaximumCertificateTimeMs = 253402300799999ULL;

bool IsDeviceIdentityTag(keymaster_tag_t tag) {
    return tag == KM_TAG_ATTESTATION_ID_BRAND || tag == KM_TAG_ATTESTATION_ID_DEVICE ||
            tag == KM_TAG_ATTESTATION_ID_PRODUCT || tag == KM_TAG_ATTESTATION_ID_SERIAL ||
            tag == KM_TAG_ATTESTATION_ID_IMEI || tag == KM_TAG_ATTESTATION_ID_MEID ||
            tag == KM_TAG_ATTESTATION_ID_MANUFACTURER || tag == KM_TAG_ATTESTATION_ID_MODEL ||
            tag == KM_TAG_ATTESTATION_ID_SECOND_IMEI;
}

void Require(bool condition, const char* code) {
    if (!condition) throw std::runtime_error(code);
}

void AddRootExtension(X509* root, int nid, const char* value) {
    bssl::UniquePtr<X509_EXTENSION> extension(X509V3_EXT_nconf_nid(nullptr, nullptr, nid, value));
    Require(extension && X509_add_ext(root, extension.get(), -1) == 1, "LAB_CA_EXTENSION");
}
}  // namespace

struct LabSoftwareAttestation::Impl {
    bssl::UniquePtr<EVP_PKEY> signing_key;
    keymaster::X509_Ptr root;
    keymaster::KeymasterBlob issuer_subject;
    mutable std::mutex mutex;

    Impl() {
        bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        signing_key.reset(EVP_PKEY_new());
        Require(ec && signing_key && EC_KEY_generate_key(ec.get()) == 1 &&
                EVP_PKEY_set1_EC_KEY(signing_key.get(), ec.get()) == 1, "LAB_CA_KEY_GENERATION");
        keymaster::CertificateCallerParams parameters{};
        parameters.serial.reset(BN_new());
        std::array<uint8_t, 16> serial{};
        Require(parameters.serial && RAND_bytes(serial.data(), serial.size()) == 1, "LAB_CA_SERIAL");
        serial[0] = static_cast<uint8_t>((serial[0] & 0x7f) | 0x01);
        Require(BN_bin2bn(serial.data(), serial.size(), parameters.serial.get()) != nullptr,
                "LAB_CA_SERIAL_ENCODING");
        Require(keymaster::make_name_from_str("AndroidLab Software Attestation Root",
                &parameters.subject_name) == KM_ERROR_OK, "LAB_CA_SUBJECT");
        parameters.active_date_time = 0;
        parameters.expire_date_time = static_cast<int64_t>(kMaximumCertificateTimeMs);
        Require(keymaster::make_cert(signing_key.get(), parameters.subject_name.get(), parameters,
                &root) == KM_ERROR_OK, "LAB_CA_CERTIFICATE");
        const int old_usage = X509_get_ext_by_NID(root.get(), NID_key_usage, -1);
        Require(old_usage >= 0, "LAB_CA_KEY_USAGE");
        bssl::UniquePtr<X509_EXTENSION> removed(X509_delete_ext(root.get(), old_usage));
        AddRootExtension(root.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
        AddRootExtension(root.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
        Require(keymaster::sign_cert(root.get(), signing_key.get()) == KM_ERROR_OK &&
                X509_verify(root.get(), signing_key.get()) == 1, "LAB_CA_SELF_SIGNATURE");
        const int subject_size = i2d_X509_NAME(parameters.subject_name.get(), nullptr);
        Require(subject_size > 0 && issuer_subject.Reset(subject_size), "LAB_CA_ISSUER_SIZE");
        uint8_t* cursor = issuer_subject.writable_data();
        Require(i2d_X509_NAME(parameters.subject_name.get(), &cursor) == subject_size &&
                cursor == issuer_subject.end(), "LAB_CA_ISSUER_ENCODING");
    }
};

LabSoftwareAttestation::LabSoftwareAttestation()
    : AttestationContext(keymaster::KmVersion::KEYMINT_3), impl_(std::make_unique<Impl>()) {}
LabSoftwareAttestation::~LabSoftwareAttestation() = default;

std::vector<uint8_t> LabSoftwareAttestation::PublicRootCertificate() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const int size = i2d_X509(impl_->root.get(), nullptr);
    Require(size > 0 && size <= 16384, "LAB_PUBLIC_ROOT_SIZE");
    std::vector<uint8_t> certificate(static_cast<size_t>(size));
    uint8_t* cursor = certificate.data();
    Require(i2d_X509(impl_->root.get(), &cursor) == size &&
            cursor == certificate.data() + certificate.size(), "LAB_PUBLIC_ROOT_ENCODING");
    return certificate;
}

keymaster_error_t LabSoftwareAttestation::ValidateRequest(const keymaster::AuthorizationSet& parameters,
        bool require_challenge) {
    using namespace keymaster;
    if (parameters.is_valid() != AuthorizationSet::OK) return KM_ERROR_INVALID_ARGUMENT;
    std::set<keymaster_tag_t> seen;
    for (const auto& entry : parameters) {
        if (IsDeviceIdentityTag(entry.tag)) return KM_ERROR_CANNOT_ATTEST_IDS;
        if (entry.tag == KM_TAG_INCLUDE_UNIQUE_ID || entry.tag == KM_TAG_DEVICE_UNIQUE_ATTESTATION ||
                entry.tag == KM_TAG_RESET_SINCE_ID_ROTATION) return KM_ERROR_UNIMPLEMENTED;
        if (entry.tag == KM_TAG_ROOT_OF_TRUST ||
                (entry.tag == KM_TAG_PURPOSE && entry.enumerated == KM_PURPOSE_ATTEST_KEY))
            return KM_ERROR_UNIMPLEMENTED;
        switch (entry.tag) {
            case KM_TAG_ATTESTATION_CHALLENGE:
            case KM_TAG_ATTESTATION_APPLICATION_ID:
            case KM_TAG_CERTIFICATE_SERIAL:
            case KM_TAG_CERTIFICATE_SUBJECT:
                if (!seen.insert(entry.tag).second) return KM_ERROR_INVALID_TAG;
                if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
                if (entry.tag == KM_TAG_ATTESTATION_CHALLENGE && entry.blob.data_length > 128)
                    return KM_ERROR_INVALID_INPUT_LENGTH;
                if (entry.tag == KM_TAG_ATTESTATION_APPLICATION_ID && entry.blob.data_length > 16384)
                    return KM_ERROR_INVALID_INPUT_LENGTH;
                if (entry.tag == KM_TAG_CERTIFICATE_SERIAL &&
                        (!entry.blob.data_length || entry.blob.data_length > 20)) return KM_ERROR_INVALID_ARGUMENT;
                if (entry.tag == KM_TAG_CERTIFICATE_SUBJECT && entry.blob.data_length > 4096)
                    return KM_ERROR_INVALID_ARGUMENT;
                if (entry.tag == KM_TAG_CERTIFICATE_SUBJECT && entry.blob.data_length) {
                    const uint8_t* cursor = entry.blob.data;
                    bssl::UniquePtr<X509_NAME> subject(d2i_X509_NAME(nullptr, &cursor, entry.blob.data_length));
                    if (!subject || cursor != entry.blob.data + entry.blob.data_length) return KM_ERROR_INVALID_ARGUMENT;
                }
                break;
            case KM_TAG_CERTIFICATE_NOT_BEFORE:
            case KM_TAG_CERTIFICATE_NOT_AFTER:
                if (!seen.insert(entry.tag).second) return KM_ERROR_INVALID_TAG;
                if (entry.date_time > kMaximumCertificateTimeMs) return KM_ERROR_INVALID_ARGUMENT;
                break;
            default:
                break;
        }
    }
    if (!parameters.Contains(TAG_ATTESTATION_CHALLENGE))
        return require_challenge ? KM_ERROR_ATTESTATION_CHALLENGE_MISSING : KM_ERROR_OK;
    if (!parameters.Contains(TAG_ATTESTATION_APPLICATION_ID)) return KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
    uint64_t before = 0, after = 0;
    if (!parameters.GetTagValue(TAG_CERTIFICATE_NOT_BEFORE, &before)) return KM_ERROR_MISSING_NOT_BEFORE;
    if (!parameters.GetTagValue(TAG_CERTIFICATE_NOT_AFTER, &after)) return KM_ERROR_MISSING_NOT_AFTER;
    return before <= after ? KM_ERROR_OK : KM_ERROR_INVALID_ARGUMENT;
}

keymaster::CertificateChain LabSoftwareAttestation::Generate(const EVP_PKEY* public_key,
        const keymaster::AuthorizationSet& software, const keymaster::AuthorizationSet& hardware,
        const keymaster::AuthorizationSet& parameters, keymaster_error_t* error) const {
    using namespace keymaster;
    if (!error) return {};
    *error = KM_ERROR_UNKNOWN_ERROR;
    try {
        *error = ValidateRequest(parameters);
        if (*error != KM_ERROR_OK) return {};
        if (!hardware.empty()) { *error = KM_ERROR_UNIMPLEMENTED; return {}; }
        keymaster_algorithm_t algorithm;
        if (!public_key || !software.GetTagValue(TAG_ALGORITHM, &algorithm) ||
                !((algorithm == KM_ALGORITHM_RSA && EVP_PKEY_id(public_key) == EVP_PKEY_RSA) ||
                  (algorithm == KM_ALGORITHM_EC && EVP_PKEY_id(public_key) == EVP_PKEY_EC))) {
            *error = KM_ERROR_INCOMPATIBLE_ALGORITHM; return {};
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        AttestKeyInfo signer;
        *error = KM_ERROR_UNKNOWN_ERROR;
        if (EVP_PKEY_up_ref(impl_->signing_key.get()) != 1) return {};
        signer.signing_key.reset(impl_->signing_key.get());
        signer.issuer_subject = &impl_->issuer_subject;
        auto leaf = generate_attestation(public_key, software, hardware, parameters, std::move(signer), *this, error);
        if (*error != KM_ERROR_OK) return {};
        if (leaf.entry_count != 1 || !leaf.entries) { *error = KM_ERROR_UNKNOWN_ERROR; return {}; }
        CertificateChain output(2);
        if (!output.entries) { *error = KM_ERROR_MEMORY_ALLOCATION_FAILED; return {}; }
        output.entries[0].data = dup_buffer(leaf.entries[0].data, leaf.entries[0].data_length);
        output.entries[0].data_length = leaf.entries[0].data_length;
        if (!output.entries[0].data) { *error = KM_ERROR_MEMORY_ALLOCATION_FAILED; return {}; }
        *error = encode_certificate(impl_->root.get(), &output.entries[1]);
        if (*error != KM_ERROR_OK) return {};
        return output;
    } catch (const std::bad_alloc&) { *error = KM_ERROR_MEMORY_ALLOCATION_FAILED; }
      catch (...) { *error = KM_ERROR_UNKNOWN_ERROR; }
    return {};
}

keymaster::CertificateChain LabSoftwareAttestation::Generate(const keymaster::Key& key,
        const keymaster::AuthorizationSet& parameters, keymaster_error_t* error) const {
    using namespace keymaster;
    if (!error) return {};
    UniquePtr<uint8_t[]> material;
    size_t size = 0;
    *error = key.formatted_key_material(KM_KEY_FORMAT_X509, &material, &size);
    if (*error != KM_ERROR_OK) return {};
    const uint8_t* cursor = material.get();
    bssl::UniquePtr<EVP_PKEY> public_key(d2i_PUBKEY(nullptr, &cursor, size));
    if (!public_key || cursor != material.get() + size) { *error = KM_ERROR_INVALID_KEY_BLOB; return {}; }
    return Generate(public_key.get(), key.sw_enforced(), key.hw_enforced(), parameters, error);
}

keymaster_security_level_t LabSoftwareAttestation::GetSecurityLevel() const { return KM_SECURITY_LEVEL_SOFTWARE; }
keymaster::KeymasterKeyBlob LabSoftwareAttestation::GetAttestationKey(keymaster_algorithm_t, keymaster_error_t* error) const {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
}
keymaster::CertificateChain LabSoftwareAttestation::GetAttestationChain(keymaster_algorithm_t, keymaster_error_t* error) const {
    if (error) *error = KM_ERROR_UNIMPLEMENTED;
    return {};
}
}  // namespace androidlab
