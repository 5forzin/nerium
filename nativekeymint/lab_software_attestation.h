#pragma once

#include <memory>
#include <vector>

#include <keymaster/attestation_context.h>
#include <openssl/base.h>

namespace androidlab {

// An ephemeral laboratory CA. Its certificates establish no manufacturer or
// Google trust, and its signing key is never serialized or persisted.
class LabSoftwareAttestation final : public keymaster::AttestationContext {
 public:
    LabSoftwareAttestation();
    ~LabSoftwareAttestation() override;
    LabSoftwareAttestation(const LabSoftwareAttestation&) = delete;
    LabSoftwareAttestation& operator=(const LabSoftwareAttestation&) = delete;

    std::vector<uint8_t> PublicRootCertificate() const;

    static keymaster_error_t ValidateRequest(const keymaster::AuthorizationSet& parameters,
            bool require_challenge = true);
    keymaster::CertificateChain Generate(const EVP_PKEY* public_key,
            const keymaster::AuthorizationSet& software,
            const keymaster::AuthorizationSet& hardware,
            const keymaster::AuthorizationSet& parameters, keymaster_error_t* error) const;
    keymaster::CertificateChain Generate(const keymaster::Key& key,
            const keymaster::AuthorizationSet& parameters, keymaster_error_t* error) const;

    keymaster_security_level_t GetSecurityLevel() const override;
    keymaster::KeymasterKeyBlob GetAttestationKey(keymaster_algorithm_t, keymaster_error_t* error) const override;
    keymaster::CertificateChain GetAttestationChain(keymaster_algorithm_t, keymaster_error_t* error) const override;

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace androidlab
