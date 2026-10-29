#include <errno.h>
#include <time.h>

int main(void) {
    struct timespec remaining = {.tv_sec = 120};
    while (nanosleep(&remaining, &remaining) == -1 && errno == EINTR) {
    }
    return 0;
}
