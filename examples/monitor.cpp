// I/O readiness with Monitor: wait on one descriptor, then on a set.

#include <taskpp/taskpp.hpp>

#include <cstdio>
#include <thread>

#include <fcntl.h>
#include <unistd.h>

using namespace taskpp;

Task<void> reader(int a, int b) {
    // --> to monitor single FD.
    int e = co_await Monitor::wait(a, FD_READ);
    std::printf("a ready: read=%d hangup=%d\n", !!(e & FD_READ), !!(e & FD_HANGUP));

    char buffer[16];
    [[maybe_unused]] auto n = ::read(a, buffer, sizeof(buffer));

    // --> to monitor multiple FD-set, with a timeout through a canceller.
    CancellerSource timeout;
    timeout.cancelAfter(TimeSpan::fromSeconds(2));

    std::vector<IoEventInfo> eves = co_await Monitor::whenAny({ a, b }, FD_READ, timeout.canceller);
    for (auto& info : eves) {
        std::printf("fd %d ready (events %d), is b: %s\n", info.fd, info.e, info.fd == b ? "yes" : "no");
    }
}

int main() {
    int p1[2], p2[2];
    if (::pipe(p1) != 0 || ::pipe(p2) != 0) {
        return 1;
    }

    std::thread writer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        [[maybe_unused]] auto r1 = ::write(p1[1], "x", 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        [[maybe_unused]] auto r2 = ::write(p2[1], "y", 1);
    });

    Worker::defaultWorker()->sync_wait(reader(p1[0], p2[0]));
    writer.join();

    for (int fd : { p1[0], p1[1], p2[0], p2[1] }) {
        ::close(fd);
    }
    return 0;
}
