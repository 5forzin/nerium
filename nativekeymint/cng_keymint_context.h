#pragma once

#include <memory>

#include <keymaster/keymaster_context.h>
#include <keymaster/km_version.h>

namespace androidlab {
class LabSoftwareAttestation;

// Process-local RSA signing adapter. KeyMint 3 returns ordinary self-signed
// certificates or an explicitly supplied laboratory SOFTWARE attestation CA.
// No TEE attestation, persistent blobs, remote provisioning, or rollback protection.
std::unique_ptr<keymaster::KeymasterContext> CreateCngKeymasterContext(
    keymaster::KmVersion version = keymaster::KmVersion::KEYMASTER_4_1,
    std::shared_ptr<LabSoftwareAttestation> lab_attestation = {});

}  // namespace androidlab
