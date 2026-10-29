#pragma once
#include <android/log.h>
#include <cstdlib>
#include <sstream>

namespace androidlab {
class CheckLog {
 public:
  explicit CheckLog(bool passed) : failed_(!passed) {}
  template<class T> CheckLog& operator<<(const T& value) { if (failed_) text_ << value; return *this; }
  ~CheckLog() {
    if (failed_) {
      __android_log_write(ANDROID_LOG_FATAL, "androidlab-keymint", text_.str().c_str());
      std::abort();
    }
  }
 private:
  bool failed_;
  std::ostringstream text_;
};
}
#define CHECK(condition) ::androidlab::CheckLog(static_cast<bool>(condition))
