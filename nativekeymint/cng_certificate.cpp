#include "cng_certificate.h"

#include <keymaster/keymaster_tags.h>
#include <keymaster/km_openssl/certificate_utils.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <limits>
#include <new>
#include <set>
#include <stdexcept>
#include <vector>

namespace androidlab {
namespace {

using namespace keymaster;
constexpr size_t kMaximumCertificateBytes = 16384;
constexpr uint64_t kMaximumCertificateTimeMs = 253402300799999ULL;

// RFC 4055: rsassaPss, SHA256, MGF1(SHA256), saltLength 32; trailerField defaults to 1.
// Both X.509 signature AlgorithmIdentifiers must use these exact parameters.
constexpr uint8_t kPssSha256Algorithm[] = {
    0x30,0x41,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0a,
    0x30,0x34,0xa0,0x0f,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,
    0x03,0x04,0x02,0x01,0x05,0x00,0xa1,0x1c,0x30,0x1a,0x06,0x09,0x2a,
    0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x08,0x30,0x0d,0x06,0x09,0x60,
    0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0xa2,0x03,0x02,
    0x01,0x20};

uint32_t Le32(const uint8_t* bytes) {
  return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
         (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}

bssl::UniquePtr<EVP_PKEY> PublicKey(const std::vector<uint8_t>& blob) {
  if (blob.size() != 283 || Le32(blob.data()) != 0x31415352 ||
      Le32(blob.data()+4) != 2048 || Le32(blob.data()+8) != 3 ||
      Le32(blob.data()+12) != 256 || Le32(blob.data()+16) != 0 ||
      Le32(blob.data()+20) != 0 || blob[24] != 1 || blob[25] != 0 || blob[26] != 1)
    throw std::runtime_error("CNG_CERT_PUBLIC_BLOB_INVALID");
  bssl::UniquePtr<BIGNUM> exponent(BN_bin2bn(blob.data()+24,3,nullptr));
  bssl::UniquePtr<BIGNUM> modulus(BN_bin2bn(blob.data()+27,256,nullptr));
  bssl::UniquePtr<RSA> rsa(RSA_new());
  bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
  if (!exponent || !modulus || !rsa || !key) throw std::bad_alloc();
  if (BN_num_bits(modulus.get()) != 2048 ||
      RSA_set0_key(rsa.get(),modulus.get(),exponent.get(),nullptr) != 1)
    throw std::runtime_error("CNG_CERT_PUBLIC_PARAMETERS_INVALID");
  modulus.release(); exponent.release();
  if (EVP_PKEY_set1_RSA(key.get(),rsa.get()) != 1)
    throw std::runtime_error("CNG_CERT_PUBLIC_KEY_INVALID");
  return key;
}

keymaster_error_t CheckParameters(const AuthorizationSet& parameters) {
  if (parameters.is_valid() != AuthorizationSet::OK) return KM_ERROR_INVALID_ARGUMENT;
  if (parameters.Contains(TAG_ATTESTATION_CHALLENGE)) return KM_ERROR_UNIMPLEMENTED;
  std::set<keymaster_tag_t> seen;
  for (const auto& entry : parameters) {
    switch (entry.tag) {
      case KM_TAG_CERTIFICATE_SERIAL:
      case KM_TAG_CERTIFICATE_SUBJECT:
        if (!seen.insert(entry.tag).second) return KM_ERROR_INVALID_TAG;
        if (entry.blob.data_length && !entry.blob.data) return KM_ERROR_INVALID_ARGUMENT;
        if (entry.tag == KM_TAG_CERTIFICATE_SERIAL &&
            (entry.blob.data_length == 0 || entry.blob.data_length > 20))
          return KM_ERROR_INVALID_ARGUMENT;
        if (entry.tag == KM_TAG_CERTIFICATE_SUBJECT && entry.blob.data_length > 4096)
          return KM_ERROR_INVALID_ARGUMENT;
        if (entry.tag == KM_TAG_CERTIFICATE_SUBJECT && entry.blob.data_length) {
          const uint8_t* cursor = entry.blob.data;
          bssl::UniquePtr<X509_NAME> subject(d2i_X509_NAME(nullptr,&cursor,entry.blob.data_length));
          if (!subject || cursor != entry.blob.data + entry.blob.data_length)
            return KM_ERROR_INVALID_ARGUMENT;
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
  uint64_t before=0,after=0;
  if (!parameters.GetTagValue(TAG_CERTIFICATE_NOT_BEFORE,&before)) return KM_ERROR_MISSING_NOT_BEFORE;
  if (!parameters.GetTagValue(TAG_CERTIFICATE_NOT_AFTER,&after)) return KM_ERROR_MISSING_NOT_AFTER;
  return before <= after ? KM_ERROR_OK : KM_ERROR_INVALID_ARGUMENT;
}

}  // namespace

keymaster::CertificateChain GenerateCngSelfSignedCertificate(
    CngKeyStore& store, const CngKeyStore::KeyId& id,
    const keymaster::AuthorizationSet& parameters, keymaster_error_t* error) {
  CertificateChain chain;
  if (!error) return chain;
  *error = KM_ERROR_UNKNOWN_ERROR;
  try {
    *error = CheckParameters(parameters);
    if (*error != KM_ERROR_OK) return chain;
    CertificateCallerParams caller;
    *error = get_certificate_params(parameters,&caller,KmVersion::KEYMINT_3);
    if (*error != KM_ERROR_OK) return chain;
    caller.is_signing_key=true;
    caller.is_encryption_key=false;
    caller.is_agreement_key=false;
    auto public_key=PublicKey(store.PublicBlob(id));
    X509_Ptr certificate;
    *error=make_cert(public_key.get(),caller.subject_name.get(),caller,&certificate);
    if (*error != KM_ERROR_OK) return chain;
    const uint8_t* algorithm_cursor=kPssSha256Algorithm;
    bssl::UniquePtr<X509_ALGOR> algorithm(d2i_X509_ALGOR(nullptr,&algorithm_cursor,sizeof(kPssSha256Algorithm)));
    if (!algorithm || algorithm_cursor != kPssSha256Algorithm+sizeof(kPssSha256Algorithm) ||
        X509_set1_signature_algo(certificate.get(),algorithm.get()) != 1) {
      *error=KM_ERROR_UNKNOWN_ERROR; return chain;
    }
    const int tbs_size=i2d_re_X509_tbs(certificate.get(),nullptr);
    if (tbs_size <= 0 || static_cast<size_t>(tbs_size) > kMaximumCertificateBytes) {
      *error=KM_ERROR_UNKNOWN_ERROR; return chain;
    }
    std::vector<uint8_t> tbs(static_cast<size_t>(tbs_size));
    uint8_t* tbs_cursor=tbs.data();
    if (i2d_re_X509_tbs(certificate.get(),&tbs_cursor) != tbs_size || tbs_cursor != tbs.data()+tbs.size()) {
      *error=KM_ERROR_UNKNOWN_ERROR; return chain;
    }
    std::array<uint8_t,SHA256_DIGEST_LENGTH> digest{};
    if (!SHA256(tbs.data(),tbs.size(),digest.data())) { *error=KM_ERROR_UNKNOWN_ERROR; return chain; }
    const auto signature=store.SignSha256(id,digest);
    if (signature.size() != 256 ||
        X509_set1_signature_value(certificate.get(),signature.data(),signature.size()) != 1 ||
        X509_verify(certificate.get(),public_key.get()) != 1) {
      *error=KM_ERROR_VERIFICATION_FAILED; return chain;
    }
    // Parse the final DER independently of the mutable builder before returning it.
    const int certificate_size=i2d_X509(certificate.get(),nullptr);
    if (certificate_size <= 0 || static_cast<size_t>(certificate_size) > kMaximumCertificateBytes) {
      *error=KM_ERROR_UNKNOWN_ERROR; return chain;
    }
    std::vector<uint8_t> der(static_cast<size_t>(certificate_size));
    uint8_t* der_cursor=der.data();
    if (i2d_X509(certificate.get(),&der_cursor) != certificate_size || der_cursor != der.data()+der.size()) {
      *error=KM_ERROR_UNKNOWN_ERROR; return chain;
    }
    const uint8_t* parse_cursor=der.data();
    X509_Ptr parsed(d2i_X509(nullptr,&parse_cursor,der.size()));
    if (!parsed || parse_cursor != der.data()+der.size()) {
      *error=KM_ERROR_VERIFICATION_FAILED; return chain;
    }
    bssl::UniquePtr<EVP_PKEY> parsed_public(X509_get_pubkey(parsed.get()));
    const X509_ALGOR* outer_algorithm=nullptr;
    X509_get0_signature(nullptr,&outer_algorithm,parsed.get());
    if (!parsed_public || EVP_PKEY_cmp(parsed_public.get(),public_key.get()) != 1 ||
        !outer_algorithm || X509_ALGOR_cmp(outer_algorithm,X509_get0_tbs_sigalg(parsed.get())) != 0 ||
        X509_ALGOR_cmp(outer_algorithm,algorithm.get()) != 0 ||
        X509_NAME_cmp(X509_get_subject_name(parsed.get()),X509_get_issuer_name(parsed.get())) != 0 ||
        X509_verify(parsed.get(),parsed_public.get()) != 1) {
      *error=KM_ERROR_VERIFICATION_FAILED; return chain;
    }
    CertificateChain output(1);
    if (!output.entries) { *error=KM_ERROR_MEMORY_ALLOCATION_FAILED; return chain; }
    *error=encode_certificate(parsed.get(),&output.entries[0]);
    if (*error != KM_ERROR_OK) return chain;
    return output;
  } catch (const std::bad_alloc&) { *error=KM_ERROR_MEMORY_ALLOCATION_FAILED; }
    catch (...) { *error=KM_ERROR_UNKNOWN_ERROR; }
  return chain;
}

}  // namespace androidlab
