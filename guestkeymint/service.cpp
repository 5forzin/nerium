#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "guest_channel.h"
#include "guest/hals/keymint/remote/remote_keymint_device.h"
#include "guest/hals/keymint/remote/remote_shared_secret.h"
#include "guest/hals/keymint/remote/remote_secure_clock.h"
#include "unsupported_rkp.h"

namespace {
template<class T> bool Register(const std::shared_ptr<T>& service) {
  const std::string instance = std::string(T::descriptor) + "/default";
  const binder_status_t result =
      AServiceManager_addService(service->asBinder().get(), instance.c_str());
  if (result != STATUS_OK) {
    fprintf(stderr, "Service registration failed: %s (%d)\n", instance.c_str(), result);
    return false;
  }
  fprintf(stderr, "Registered %s\n", instance.c_str());
  return true;
}
}

int main(int argc, char** argv) {
  if (argc != 2 || strncmp(argv[1], "/dev/vport", 10) != 0) {
    fprintf(stderr, "Usage: androidlab-keymint-service /dev/vportXpY\n");
    return 2;
  }
  signal(SIGPIPE, SIG_IGN);
  const int fd = open(argv[1], O_RDWR | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) { perror("open virtio serial port"); return 1; }
  androidlab::GuestChannel channel(fd);
  keymaster::RemoteKeymaster remote(&channel, 4);
  using namespace aidl::android::hardware::security::keymint;
  auto service = ndk::SharedRefBase::make<RemoteKeyMintDevice>(remote, SecurityLevel::SOFTWARE);
  auto secret = ndk::SharedRefBase::make<aidl::android::hardware::security::sharedsecret::RemoteSharedSecret>(remote);
  auto clock = ndk::SharedRefBase::make<aidl::android::hardware::security::secureclock::RemoteSecureClock>(remote);
  auto rkp = ndk::SharedRefBase::make<androidlab::UnsupportedRkp>();
  ABinderProcess_setThreadPoolMaxThreadCount(0);
  if (!Register(service) || !Register(secret) || !Register(clock) || !Register(rkp)) return 1;
  ABinderProcess_joinThreadPool();
  return 1;
}
