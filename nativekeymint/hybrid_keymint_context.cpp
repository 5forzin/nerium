#include "hybrid_keymint_context.h"
#include "cng_keymint_context.h"
#include "lab_software_attestation.h"

#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/key.h>
#include <keymaster/key_factory.h>
#include <keymaster/keymaster_tags.h>

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <utility>

namespace androidlab {
namespace {
using namespace keymaster;

bool IsCngReference(const KeymasterKeyBlob& blob) {
    constexpr std::array<uint8_t, 4> version{{1, 0, 0, 0}};
    return blob.size() == 36 && blob.begin() &&
            std::equal(version.begin(), version.end(), blob.begin());
}

bool IsProtectedProfile(const AuthorizationSet& parameters, bool lab_attestation) {
    if (parameters.is_valid() != AuthorizationSet::OK) return false;
    std::set<keymaster_tag_t> seen;
    for (const auto& entry : parameters) {
        seen.insert(entry.tag);
        switch (entry.tag) {
            case KM_TAG_ALGORITHM:
                if (entry.enumerated != KM_ALGORITHM_RSA) return false;
                break;
            case KM_TAG_KEY_SIZE:
                if (entry.integer != 2048) return false;
                break;
            case KM_TAG_PURPOSE:
                if (entry.enumerated != KM_PURPOSE_SIGN) return false;
                break;
            case KM_TAG_DIGEST:
                if (entry.enumerated != KM_DIGEST_SHA_2_256) return false;
                break;
            case KM_TAG_PADDING:
                if (entry.enumerated != KM_PAD_RSA_PSS) return false;
                break;
            case KM_TAG_RSA_PUBLIC_EXPONENT:
                if (entry.long_integer != 65537) return false;
                break;
            case KM_TAG_NO_AUTH_REQUIRED:
                if (!entry.boolean) return false;
                break;
            case KM_TAG_APPLICATION_ID:
            case KM_TAG_APPLICATION_DATA:
            case KM_TAG_CERTIFICATE_SERIAL:
            case KM_TAG_CERTIFICATE_SUBJECT:
            case KM_TAG_CERTIFICATE_NOT_BEFORE:
            case KM_TAG_CERTIFICATE_NOT_AFTER:
            case KM_TAG_CREATION_DATETIME:
            case KM_TAG_ATTESTATION_CHALLENGE:
            case KM_TAG_INCLUDE_UNIQUE_ID:
            case KM_TAG_DEVICE_UNIQUE_ATTESTATION:
            case KM_TAG_RESET_SINCE_ID_ROTATION:
                break;
            case KM_TAG_ATTESTATION_APPLICATION_ID:
                if (!lab_attestation) return false;
                break;
            default:
                // A malformed type on this neutral metadata tag must fail in
                // the selected CNG validator instead of changing key providers.
                if (keymaster_tag_mask_type(entry.tag) == keymaster_tag_mask_type(KM_TAG_CREATION_DATETIME))
                    break;
                return false;
        }
    }
    for (const auto tag : {KM_TAG_ALGORITHM, KM_TAG_KEY_SIZE, KM_TAG_PURPOSE, KM_TAG_DIGEST,
            KM_TAG_PADDING, KM_TAG_RSA_PUBLIC_EXPONENT, KM_TAG_NO_AUTH_REQUIRED}) {
        if (seen.count(tag) != 1) return false;
    }
    return true;
}

class HybridAsymmetricFactory final : public KeyFactory {
 public:
    HybridAsymmetricFactory(const KeyFactory& software, const KeyFactory* cng,
            std::shared_ptr<LabSoftwareAttestation> lab_attestation)
        : software_(software), cng_(cng), lab_attestation_(std::move(lab_attestation)) {}

    keymaster_error_t GenerateKey(const AuthorizationSet& description, UniquePtr<Key> attest_key,
            const KeymasterBlob& issuer_subject, KeymasterKeyBlob* blob, AuthorizationSet* hardware,
            AuthorizationSet* software, CertificateChain* chain) const override {
        // Selection happens before generation. A selected CNG failure is final.
        if (lab_attestation_) {
            if (attest_key || issuer_subject.size()) return KM_ERROR_UNIMPLEMENTED;
            const auto error = LabSoftwareAttestation::ValidateRequest(description, false);
            if (error != KM_ERROR_OK) return error;
        }
        const auto& factory = cng_ && IsProtectedProfile(description, lab_attestation_ != nullptr) ? *cng_ : software_;
        return factory.GenerateKey(description, std::move(attest_key), issuer_subject,
                blob, hardware, software, chain);
    }
    keymaster_error_t ImportKey(const AuthorizationSet& description, keymaster_key_format_t format,
            const KeymasterKeyBlob& material, UniquePtr<Key> attest_key, const KeymasterBlob& issuer_subject,
            KeymasterKeyBlob* blob, AuthorizationSet* hardware, AuthorizationSet* software,
            CertificateChain* chain) const override {
        if (lab_attestation_) {
            if (attest_key || issuer_subject.size()) return KM_ERROR_UNIMPLEMENTED;
            const auto error = LabSoftwareAttestation::ValidateRequest(description, false);
            if (error != KM_ERROR_OK) return error;
        }
        return software_.ImportKey(description, format, material, std::move(attest_key),
                issuer_subject, blob, hardware, software, chain);
    }
    keymaster_error_t LoadKey(KeymasterKeyBlob&& material, const AuthorizationSet& additional,
            AuthorizationSet&& hardware, AuthorizationSet&& software, UniquePtr<Key>* key) const override {
        // PureSoft ParseKeyBlob already decoded the software blob. This material
        // is private key DER, not the opaque reference handled by the outer context.
        return software_.LoadKey(std::move(material), additional, std::move(hardware),
                std::move(software), key);
    }
    OperationFactory* GetOperationFactory(keymaster_purpose_t purpose) const override {
        // Actual BeginOperation uses the factory carried by the parsed Key.
        return software_.GetOperationFactory(purpose);
    }
    const keymaster_key_format_t* SupportedImportFormats(size_t* count) const override {
        return software_.SupportedImportFormats(count);
    }
    const keymaster_key_format_t* SupportedExportFormats(size_t* count) const override {
        return software_.SupportedExportFormats(count);
    }

 private:
    const KeyFactory& software_;
    const KeyFactory* cng_;
    std::shared_ptr<LabSoftwareAttestation> lab_attestation_;
};

class HybridKeymintContext final : public PureSoftKeymasterContext {
 public:
    explicit HybridKeymintContext(bool enable_lab_attestation)
        : PureSoftKeymasterContext(KmVersion::KEYMINT_3, KM_SECURITY_LEVEL_SOFTWARE),
          lab_attestation_(enable_lab_attestation ? std::make_shared<LabSoftwareAttestation>() : nullptr),
          cng_(CreateCngKeymasterContext(KmVersion::KEYMINT_3, lab_attestation_)),
          rsa_(SoftwareFactory(KM_ALGORITHM_RSA), &CngRsaFactory(), lab_attestation_),
          ec_(SoftwareFactory(KM_ALGORITHM_EC), nullptr, lab_attestation_) {}

    std::vector<uint8_t> PublicLabRootCertificate() const {
        return lab_attestation_ ? lab_attestation_->PublicRootCertificate() : std::vector<uint8_t>{};
    }

    KeyFactory* GetKeyFactory(keymaster_algorithm_t algorithm) const override {
        if (algorithm == KM_ALGORITHM_RSA) return &rsa_;
        if (algorithm == KM_ALGORITHM_EC && lab_attestation_) return &ec_;
        return PureSoftKeymasterContext::GetKeyFactory(algorithm);
    }
    keymaster_error_t ParseKeyBlob(const KeymasterKeyBlob& blob, const AuthorizationSet& parameters,
            UniquePtr<Key>* key) const override {
        return IsCngReference(blob) ? cng_->ParseKeyBlob(blob, parameters, key)
                : PureSoftKeymasterContext::ParseKeyBlob(blob, parameters, key);
    }
    keymaster_error_t UpgradeKeyBlob(const KeymasterKeyBlob& blob, const AuthorizationSet& parameters,
            KeymasterKeyBlob* upgraded) const override {
        return IsCngReference(blob) ? cng_->UpgradeKeyBlob(blob, parameters, upgraded)
                : PureSoftKeymasterContext::UpgradeKeyBlob(blob, parameters, upgraded);
    }
    keymaster_error_t DeleteKey(const KeymasterKeyBlob& blob) const override {
        return IsCngReference(blob) ? cng_->DeleteKey(blob) : PureSoftKeymasterContext::DeleteKey(blob);
    }
    keymaster_error_t DeleteAllKeys() const override {
        const auto protected_error = cng_->DeleteAllKeys();
        const auto software_error = PureSoftKeymasterContext::DeleteAllKeys();
        return protected_error != KM_ERROR_OK ? protected_error : software_error;
    }
    keymaster_error_t SetSystemVersion(uint32_t version, uint32_t patchlevel) override {
        const auto error = cng_->SetSystemVersion(version, patchlevel);
        return error != KM_ERROR_OK ? error : PureSoftKeymasterContext::SetSystemVersion(version, patchlevel);
    }
    keymaster_error_t SetVendorPatchlevel(uint32_t patchlevel) override {
        const auto error = cng_->SetVendorPatchlevel(patchlevel);
        return error != KM_ERROR_OK ? error : PureSoftKeymasterContext::SetVendorPatchlevel(patchlevel);
    }
    keymaster_error_t SetBootPatchlevel(uint32_t patchlevel) override {
        const auto error = cng_->SetBootPatchlevel(patchlevel);
        return error != KM_ERROR_OK ? error : PureSoftKeymasterContext::SetBootPatchlevel(patchlevel);
    }
    keymaster_error_t SetVerifiedBootInfo(std::string_view state, std::string_view loader,
            const std::vector<uint8_t>& digest) override {
        const auto error = cng_->SetVerifiedBootInfo(state, loader, digest);
        return error != KM_ERROR_OK ? error : PureSoftKeymasterContext::SetVerifiedBootInfo(state, loader, digest);
    }
    CertificateChain GenerateAttestation(const Key& key, const AuthorizationSet& parameters, UniquePtr<Key> attest_key,
            const KeymasterBlob& issuer, keymaster_error_t* error) const override {
        if (lab_attestation_ && !attest_key && !issuer.size())
            return lab_attestation_->Generate(key, parameters, error);
        if (error) *error = KM_ERROR_UNIMPLEMENTED;
        return {};
    }
    Buffer GenerateUniqueId(uint64_t, const keymaster_blob_t&, bool, keymaster_error_t* error) const override {
        if (error) *error = KM_ERROR_UNIMPLEMENTED;
        return {};
    }
    KeymasterKeyBlob GetAttestationKey(keymaster_algorithm_t, keymaster_error_t* error) const override {
        if (error) *error = KM_ERROR_UNIMPLEMENTED;
        return {};
    }
    CertificateChain GetAttestationChain(keymaster_algorithm_t, keymaster_error_t* error) const override {
        if (error) *error = KM_ERROR_UNIMPLEMENTED;
        return {};
    }
    const VerifiedBootParams* GetVerifiedBootParams(keymaster_error_t* error) const override {
        if (error) *error = KM_ERROR_UNIMPLEMENTED;
        return nullptr;
    }
    RemoteProvisioningContext* GetRemoteProvisioningContext() const override { return nullptr; }

 private:
    const KeyFactory& SoftwareFactory(keymaster_algorithm_t algorithm) const {
        auto* factory = PureSoftKeymasterContext::GetKeyFactory(algorithm);
        if (!factory) throw std::runtime_error("HYBRID_SOFTWARE_FACTORY_MISSING");
        return *factory;
    }
    const KeyFactory& CngRsaFactory() const {
        const auto* factory = cng_->GetKeyFactory(KM_ALGORITHM_RSA);
        if (!factory) throw std::runtime_error("HYBRID_CNG_RSA_FACTORY_MISSING");
        return *factory;
    }
    std::shared_ptr<LabSoftwareAttestation> lab_attestation_;
    std::unique_ptr<KeymasterContext> cng_;
    mutable HybridAsymmetricFactory rsa_;
    mutable HybridAsymmetricFactory ec_;
};
}  // namespace

std::unique_ptr<keymaster::KeymasterContext> CreateHybridKeymintContext(
        bool enable_lab_attestation, std::vector<uint8_t>* public_lab_root) {
    if (public_lab_root) public_lab_root->clear();
    auto context = std::make_unique<HybridKeymintContext>(enable_lab_attestation);
    if (public_lab_root) *public_lab_root = context->PublicLabRootCertificate();
    return context;
}

}  // namespace androidlab
