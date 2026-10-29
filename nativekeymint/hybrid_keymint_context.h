#pragma once

#include <memory>
#include <vector>

#include <keymaster/keymaster_context.h>

namespace androidlab {

// Keeps stock software key formats and algorithms while routing the selected
// RSA signing profile to process-local CNG references. Reports SOFTWARE only.
// Laboratory attestation is opt-in and never establishes external root trust.
std::unique_ptr<keymaster::KeymasterContext> CreateHybridKeymintContext(
    bool enable_lab_attestation = false, std::vector<uint8_t>* public_lab_root = nullptr);

}  // namespace androidlab
