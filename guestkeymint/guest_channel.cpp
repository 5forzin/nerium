#include "guest_channel.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <vector>

namespace androidlab {
namespace {
constexpr uint32_t kResponseBit = 0x80000000;
constexpr size_t kMaximumPayload = 1024 * 1024;
constexpr int kTimeoutMilliseconds = 30000;
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
struct Header { uint32_t command; uint32_t size; };
static_assert(sizeof(Header) == 8);

struct WipedBuffer : std::vector<uint8_t> {
  using std::vector<uint8_t>::vector;
  ~WipedBuffer() {
    volatile uint8_t* p = data();
    for (size_t i = 0; i < size(); ++i) p[i] = 0;
  }
};
}  // namespace

GuestChannel::~GuestChannel() { Disconnect(); }
void GuestChannel::Disconnect() {
  if (fd_ >= 0) close(fd_);
  fd_ = -1;
}

bool GuestChannel::Transfer(void* data, size_t size, bool writing) {
  auto* p = static_cast<uint8_t*>(data);
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(kTimeoutMilliseconds);
  while (size != 0) {
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    if (remaining <= 0) return false;
    pollfd event{fd_, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    const int ready = poll(&event, 1, static_cast<int>(remaining));
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || (event.revents & (POLLERR | POLLNVAL))) return false;
    ssize_t count = writing ? write(fd_, p, size) : read(fd_, p, size);
    if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (count <= 0) return false;
    p += count;
    size -= static_cast<size_t>(count);
  }
  return true;
}

void GuestChannel::Exchange(keymaster::AndroidKeymasterCommand command,
                            const keymaster::Serializable& request,
                            keymaster::KeymasterResponse* response) {
  std::lock_guard<std::mutex> guard(mutex_);
  response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
  const auto commandNumber = static_cast<uint32_t>(command);
  const size_t requestSize = request.SerializedSize();
  if (fd_ < 0 || requestSize > kMaximumPayload || (commandNumber & kResponseBit)) return;
  WipedBuffer requestBytes(std::max<size_t>(requestSize, 1));
  if (request.Serialize(requestBytes.data(), requestBytes.data() + requestSize) !=
      requestBytes.data() + requestSize) return;
  Header header{commandNumber, static_cast<uint32_t>(requestSize)};
  if (!Transfer(&header, sizeof(header), true) ||
      !Transfer(requestBytes.data(), requestSize, true) ||
      !Transfer(&header, sizeof(header), false) ||
      header.command != (commandNumber | kResponseBit) ||
      header.size > kMaximumPayload) {
    Disconnect();
    return;
  }
  WipedBuffer responseBytes(std::max<size_t>(header.size, 1));
  if (!Transfer(responseBytes.data(), header.size, false)) {
    Disconnect();
    return;
  }
  const uint8_t* cursor = responseBytes.data();
  const uint8_t* end = cursor + header.size;
  if (!response->Deserialize(&cursor, end) || cursor != end) {
    response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    Disconnect();
  }
}
}  // namespace androidlab
