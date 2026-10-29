#pragma once

#include "cng_key_store.h"

#include <keymaster/authorization_set.h>
#include <keymaster/android_keymaster_utils.h>

namespace androidlab {

// One ordinary self-signed public-key certificate, without Android attestation extensions.
keymaster::CertificateChain GenerateCngSelfSignedCertificate(
    CngKeyStore& store, const CngKeyStore::KeyId& id,
    const keymaster::AuthorizationSet& parameters, keymaster_error_t* error);

}  // namespace androidlab
