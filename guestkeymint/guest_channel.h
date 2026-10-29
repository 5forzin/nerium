#pragma once

#include <keymaster/android_keymaster_messages.h>
#include <mutex>

namespace androidlab {

// Cuttlefish KeymasterChannel wire format, restricted to little-endian guests.
class GuestChannel {
 public:
  explicit GuestChannel(int fd) : fd_(fd) {}
  ~GuestChannel();
  GuestChannel(const GuestChannel&) = delete;
  GuestChannel& operator=(const GuestChannel&) = delete;
  void Exchange(keymaster::AndroidKeymasterCommand command,
                const keymaster::Serializable& request,
                keymaster::KeymasterResponse* response);

 private:
  bool Transfer(void* data, size_t size, bool writing);
  void Disconnect();
  int fd_;
  std::mutex mutex_;
};

}  // namespace androidlab
