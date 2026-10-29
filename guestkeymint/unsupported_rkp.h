#pragma once
#include <aidl/android/hardware/security/keymint/BnRemotelyProvisionedComponent.h>

namespace androidlab {
class UnsupportedRkp final : public aidl::android::hardware::security::keymint::BnRemotelyProvisionedComponent {
  using RpcHardwareInfo = aidl::android::hardware::security::keymint::RpcHardwareInfo;
  using MacedPublicKey = aidl::android::hardware::security::keymint::MacedPublicKey;
  using DeviceInfo = aidl::android::hardware::security::keymint::DeviceInfo;
  using ProtectedData = aidl::android::hardware::security::keymint::ProtectedData;
  static ndk::ScopedAStatus Unsupported() {
    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
  }
 public:
  ndk::ScopedAStatus getHardwareInfo(RpcHardwareInfo*) override { return Unsupported(); }
  ndk::ScopedAStatus generateEcdsaP256KeyPair(bool, MacedPublicKey*, std::vector<uint8_t>*) override {
    return Unsupported();
  }
  ndk::ScopedAStatus generateCertificateRequest(bool, const std::vector<MacedPublicKey>&,
      const std::vector<uint8_t>&, const std::vector<uint8_t>&, DeviceInfo*,
      ProtectedData*, std::vector<uint8_t>*) override { return Unsupported(); }
  ndk::ScopedAStatus generateCertificateRequestV2(const std::vector<MacedPublicKey>&,
      const std::vector<uint8_t>&, std::vector<uint8_t>*) override { return Unsupported(); }
};
}  // namespace androidlab
