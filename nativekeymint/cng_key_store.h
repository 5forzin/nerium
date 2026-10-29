#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace androidlab {

class CngKeyStore final {
 public:
  using KeyId = std::array<std::uint8_t, 32>;

  CngKeyStore();
  ~CngKeyStore();
  CngKeyStore(const CngKeyStore&) = delete;
  CngKeyStore& operator=(const CngKeyStore&) = delete;
  CngKeyStore(CngKeyStore&&) = delete;
  CngKeyStore& operator=(CngKeyStore&&) = delete;

  KeyId GenerateRsaPss2048();
  std::vector<std::uint8_t> PublicBlob(const KeyId& id) const;
  std::vector<std::uint8_t> SignSha256(const KeyId& id,
                                     const std::array<std::uint8_t, 32>& digest);
  bool Delete(const KeyId& id);
  bool Contains(const KeyId& id) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace androidlab
