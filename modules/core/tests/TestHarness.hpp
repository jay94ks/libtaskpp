#pragma once
// Minimal dependency-free test harness.

#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace testing {

struct Case {
    const char* name;
    std::function<void()> body;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Failure {
    std::string message;
};

struct Registrar {
    Registrar(const char* name, std::function<void()> body) { registry().push_back({ name, std::move(body) }); }
};

inline int runAll() {
    int failed = 0;
    for (auto& c : registry()) {
        try {
            c.body();
            std::printf("[  OK  ] %s\n", c.name);
        }
        catch (const Failure& f) {
            ++failed;
            std::printf("[FAILED] %s\n         %s\n", c.name, f.message.c_str());
        }
        catch (const std::exception& e) {
            ++failed;
            std::printf("[FAILED] %s\n         unexpected exception: %s\n", c.name, e.what());
        }
    }

    std::printf("%zu tests, %d failed\n", registry().size(), failed);
    return failed ? 1 : 0;
}

} // namespace testing

#define TP_CONCAT2(a, b) a##b
#define TP_CONCAT(a, b) TP_CONCAT2(a, b)

#define TEST(name)                                                              \
    static void name();                                                         \
    static ::testing::Registrar TP_CONCAT(name, _registrar)(#name, &name);      \
    static void name()

#define CHECK(expr)                                                             \
    do {                                                                        \
        if (!(expr)) {                                                          \
            throw ::testing::Failure { std::string(__FILE__) + ":" +            \
                std::to_string(__LINE__) + ": CHECK(" #expr ") failed" };       \
        }                                                                       \
    } while (0)

#define CHECK_THROWS(type, expr)                                                \
    do {                                                                        \
        bool thrown_ = false;                                                   \
        try { (void) (expr); } catch (const type&) { thrown_ = true; }          \
        CHECK(thrown_ && "expected " #type);                                    \
    } while (0)

#define TEST_MAIN() int main() { return ::testing::runAll(); }
