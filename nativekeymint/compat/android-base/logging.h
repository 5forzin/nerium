#pragma once
#include <cstdlib>
#include <cstdio>

// Only fatal CHECK assertions are required by cppbor and the unused RKP context.
// Keep failure details out of logs; this port does not replace Keymaster logic.
namespace androidlab {
struct FatalCheck {
    FatalCheck() { std::fputs("AOSP dependency assertion failed\n", stderr); }
    template<class T> FatalCheck& operator<<(const T&) { return *this; }
    ~FatalCheck() { std::abort(); }
};
struct PortLog {
    template<class T> PortLog& operator<<(const T&) { return *this; }
    ~PortLog() { std::fputs("AOSP dependency reported an error\n", stderr); }
};
}
#define CHECK(condition) if (condition) {} else androidlab::FatalCheck()
#define CHECK_EQ(left, right) CHECK((left) == (right))
#define LOG(severity) androidlab::PortLog()
