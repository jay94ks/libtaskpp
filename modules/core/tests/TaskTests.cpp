#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <memory>
#include <stdexcept>
#include <string>

using namespace taskpp;

namespace {

Task<int> answer() { co_return 42; }

Task<int> add(int a, int b) {
    int x = co_await answer();
    co_return a + b + x - 42;
}

Task<void> fails() {
    throw std::runtime_error("boom");
    co_return;
}

Task<std::string> catches() {
    try {
        co_await fails();
    }
    catch (const std::runtime_error& e) {
        co_return std::string("caught: ") + e.what();
    }
    co_return "not caught";
}

Task<int> deep(int n) {
    if (n == 0) {
        co_return 0;
    }
    co_return 1 + co_await deep(n - 1);
}

Task<std::unique_ptr<int>> moveOnly() { co_return std::make_unique<int>(7); }

Task<void> lazy(bool* ran) {
    *ran = true;
    co_return;
}

} // namespace

TEST(task_returns_value) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(add(1, 2)) == 3);
}

TEST(task_void_and_exception) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK_THROWS(std::runtime_error, w->sync_wait(fails()));
    CHECK(w->sync_wait(catches()) == "caught: boom");
}

TEST(task_deep_recursion_uses_symmetric_transfer) {
    // GCC only turns symmetric transfer into a real tail call when optimizing;
    // unoptimized GCC builds use one stack frame per awaiting level.
#if (defined(__clang__) || defined(__OPTIMIZE__) || defined(_MSC_VER)) && !defined(__SANITIZE_THREAD__)
    constexpr int depth = 100000;
#else
    constexpr int depth = 2000;
#endif
    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(deep(depth)) == depth);
}

TEST(task_move_only_result) {
    auto w = std::make_shared<ThreadedWorker>();
    auto p = w->sync_wait(moveOnly());
    CHECK(p && *p == 7);
}

TEST(task_is_lazy) {
    bool ran = false;
    {
        auto t = lazy(&ran);
        CHECK(t.valid());
        CHECK(!t.isDone());
    }   // destroyed without running.
    CHECK(!ran);
}

TEST_MAIN()
