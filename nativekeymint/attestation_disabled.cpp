#include <keymaster/contexts/soft_attestation_cert.h>

// This harness deliberately does not link AOSP's software attestation fixture keys.
namespace keymaster {
const keymaster_key_blob_t* getAttestationKey(keymaster_algorithm_t, keymaster_error_t* error) {
    *error = KM_ERROR_UNIMPLEMENTED;
    return nullptr;
}
CertificateChain getAttestationChain(keymaster_algorithm_t, keymaster_error_t* error) {
    *error = KM_ERROR_UNIMPLEMENTED;
    return {};
}
}
