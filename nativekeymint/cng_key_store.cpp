#include "cng_key_store.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <cstring>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace androidlab {
namespace {

// WinSDK ncrypt.h, microsoft/win32metadata 2f767671802301cf043c717d66bf004ed7863487.
constexpr DWORD kRequireVbs = 0x00020000;
constexpr DWORD kSigningOnly = 0x00000002;
constexpr DWORD kPss = 0x00000008;
constexpr DWORD kRsa2048SignatureBytes = 256;
constexpr DWORD kMaximumPublicBlobBytes = 1024;
constexpr wchar_t kVirtualIsolationProperty[] = L"Virtual Iso";

[[noreturn]] void Fail(const char* stage, LONG status) {
  std::ostringstream message;
  message << stage << "_0x" << std::uppercase << std::hex << std::setw(8)
          << std::setfill('0') << static_cast<std::uint32_t>(status);
  throw std::runtime_error(message.str());
}

void Check(SECURITY_STATUS status, const char* stage) {
  if (status != ERROR_SUCCESS) Fail(stage, status);
}

class OwnedKey final {
 public:
  explicit OwnedKey(NCRYPT_KEY_HANDLE handle = 0) : handle_(handle) {}
  ~OwnedKey() { if (handle_) NCryptFreeObject(handle_); }
  OwnedKey(const OwnedKey&) = delete;
  OwnedKey& operator=(const OwnedKey&) = delete;
  OwnedKey(OwnedKey&& other) noexcept : handle_(other.release()) {}
  OwnedKey& operator=(OwnedKey&& other) noexcept {
    if (this != &other) {
      if (handle_) NCryptFreeObject(handle_);
      handle_ = other.release();
    }
    return *this;
  }
  NCRYPT_KEY_HANDLE get() const { return handle_; }
  NCRYPT_KEY_HANDLE release() noexcept { return std::exchange(handle_, 0); }

 private:
  NCRYPT_KEY_HANDLE handle_;
};

void SetDword(NCRYPT_KEY_HANDLE key, LPCWSTR property, DWORD value,
              const char* stage) {
  Check(NCryptSetProperty(key, property, reinterpret_cast<PBYTE>(&value),
                         sizeof(value), 0), stage);
}

DWORD GetDword(NCRYPT_KEY_HANDLE key, LPCWSTR property, const char* stage) {
  DWORD value = 0, bytes = 0;
  Check(NCryptGetProperty(key, property, reinterpret_cast<PBYTE>(&value),
                         sizeof(value), &bytes, 0), stage);
  if (bytes != sizeof(value)) throw std::runtime_error("CNG_PROPERTY_SIZE");
  return value;
}

std::vector<std::uint8_t> ExportPublic(NCRYPT_KEY_HANDLE key) {
  DWORD size = 0;
  Check(NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0,
                       &size, 0), "CNG_PUBLIC_SIZE");
  if (size < sizeof(BCRYPT_RSAKEY_BLOB) || size > kMaximumPublicBlobBytes)
    throw std::runtime_error("CNG_PUBLIC_SIZE_INVALID");
  std::vector<std::uint8_t> bytes(size);
  DWORD written = 0;
  Check(NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, bytes.data(),
                       size, &written, 0), "CNG_PUBLIC_EXPORT");
  if (written != size) throw std::runtime_error("CNG_PUBLIC_SIZE_INVALID");
  BCRYPT_RSAKEY_BLOB header{};
  std::memcpy(&header, bytes.data(), sizeof(header));
  if (header.Magic != BCRYPT_RSAPUBLIC_MAGIC || header.BitLength != 2048 ||
      header.cbPublicExp != 3 || header.cbModulus != 256 ||
      header.cbPrime1 != 0 || header.cbPrime2 != 0 ||
      size != sizeof(header) + 3 + 256 ||
      bytes[sizeof(header)] != 1 || bytes[sizeof(header) + 1] != 0 ||
      bytes[sizeof(header) + 2] != 1)
    throw std::runtime_error("CNG_RSA_PUBLIC_PARAMETERS_INVALID");
  return bytes;
}

}  // namespace

struct CngKeyStore::Impl {
  struct Entry {
    OwnedKey key;
    std::vector<std::uint8_t> public_blob;
  };
  NCRYPT_PROV_HANDLE provider = 0;
  mutable std::mutex mutex;
  std::map<KeyId, Entry> keys;

  Impl() {
    const auto status = NCryptOpenStorageProvider(&provider,
        MS_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
      if (provider) NCryptFreeObject(provider);
      provider = 0;
      Fail("CNG_PROVIDER_OPEN", status);
    }
  }
  ~Impl() {
    keys.clear();
    if (provider) NCryptFreeObject(provider);
  }
};

CngKeyStore::CngKeyStore() : impl_(std::make_unique<Impl>()) {}
CngKeyStore::~CngKeyStore() = default;

CngKeyStore::KeyId CngKeyStore::GenerateRsaPss2048() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  NCRYPT_KEY_HANDLE raw = 0;
  const auto status = NCryptCreatePersistedKey(impl_->provider, &raw,
      BCRYPT_RSA_ALGORITHM, nullptr, 0, kRequireVbs);
  OwnedKey key(raw);
  Check(status, "CNG_REQUIRE_VBS_CREATE_UNSUPPORTED");
  SetDword(key.get(), NCRYPT_LENGTH_PROPERTY, 2048, "CNG_RSA_LENGTH");
  SetDword(key.get(), NCRYPT_KEY_USAGE_PROPERTY, kSigningOnly, "CNG_SIGNING_USAGE");
  SetDword(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, 0, "CNG_NO_PRIVATE_EXPORT");
  Check(NCryptFinalizeKey(key.get(), 0), "CNG_REQUIRE_VBS_FINALIZE");
  if (GetDword(key.get(), kVirtualIsolationProperty, "CNG_ISOLATION_QUERY") != 1)
    throw std::runtime_error("CNG_VBS_ISOLATION_NOT_CONFIRMED");
  if (GetDword(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, "CNG_EXPORT_POLICY_QUERY") != 0)
    throw std::runtime_error("CNG_PRIVATE_EXPORT_POLICY_INVALID");
  auto public_blob = ExportPublic(key.get());
  KeyId id{};
  for (int attempt = 0; attempt < 8; ++attempt) {
    const NTSTATUS random_status = BCryptGenRandom(nullptr, id.data(),
        static_cast<ULONG>(id.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (random_status < 0) Fail("CNG_RANDOM_ID", random_status);
    if (impl_->keys.find(id) == impl_->keys.end()) {
      impl_->keys.emplace(id, Impl::Entry{std::move(key), std::move(public_blob)});
      return id;
    }
  }
  throw std::runtime_error("CNG_RANDOM_ID_COLLISION_LIMIT");
}

std::vector<std::uint8_t> CngKeyStore::PublicBlob(const KeyId& id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto entry = impl_->keys.find(id);
  if (entry == impl_->keys.end()) throw std::runtime_error("CNG_KEY_NOT_FOUND");
  return entry->second.public_blob;
}

std::vector<std::uint8_t> CngKeyStore::SignSha256(
    const KeyId& id, const std::array<std::uint8_t, 32>& digest) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto entry = impl_->keys.find(id);
  if (entry == impl_->keys.end()) throw std::runtime_error("CNG_KEY_NOT_FOUND");
  BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, 32};
  DWORD size = 0;
  auto data = const_cast<PBYTE>(digest.data());
  Check(NCryptSignHash(entry->second.key.get(), &padding, data,
      static_cast<DWORD>(digest.size()), nullptr, 0, &size, kPss), "CNG_PSS_SIZE");
  if (size != kRsa2048SignatureBytes) throw std::runtime_error("CNG_SIGNATURE_SIZE_INVALID");
  std::vector<std::uint8_t> signature(size);
  DWORD written = 0;
  Check(NCryptSignHash(entry->second.key.get(), &padding, data,
      static_cast<DWORD>(digest.size()), signature.data(), size, &written, kPss), "CNG_PSS_SIGN");
  if (written != size) throw std::runtime_error("CNG_SIGNATURE_SIZE_INVALID");
  return signature;
}

bool CngKeyStore::Delete(const KeyId& id) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto entry = impl_->keys.find(id);
  if (entry == impl_->keys.end()) return false;
  const auto key = entry->second.key.get();
  Check(NCryptFreeObject(key), "CNG_KEY_RELEASE");
  entry->second.key.release();
  impl_->keys.erase(entry);
  return true;
}

bool CngKeyStore::Contains(const KeyId& id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->keys.find(id) != impl_->keys.end();
}

}  // namespace androidlab
