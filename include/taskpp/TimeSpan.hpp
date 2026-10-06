#pragma once
#include <chrono>
#include <compare>
#include <cstdint>
#include <type_traits>

namespace taskpp {

/**
 * A signed time interval with nanosecond resolution.
 * Implicitly constructible from any `std::chrono::duration`.
 */
class TimeSpan {
public:
    using Duration = std::chrono::nanoseconds;

    constexpr TimeSpan() noexcept = default;

    template<typename Rep, typename Period>
    constexpr TimeSpan(std::chrono::duration<Rep, Period> value) noexcept
        : value_(std::chrono::duration_cast<Duration>(value)) { }

    static constexpr TimeSpan zero() noexcept { return TimeSpan(); }
    static constexpr TimeSpan max() noexcept { return TimeSpan(Duration::max()); }

    template<typename R> requires std::is_arithmetic_v<R>
    static constexpr TimeSpan fromNanoseconds(R v) noexcept { return std::chrono::duration<R, std::nano>(v); }

    template<typename R> requires std::is_arithmetic_v<R>
    static constexpr TimeSpan fromMicroseconds(R v) noexcept { return std::chrono::duration<R, std::micro>(v); }

    template<typename R> requires std::is_arithmetic_v<R>
    static constexpr TimeSpan fromMilliseconds(R v) noexcept { return std::chrono::duration<R, std::milli>(v); }

    template<typename R> requires std::is_arithmetic_v<R>
    static constexpr TimeSpan fromSeconds(R v) noexcept { return std::chrono::duration<R>(v); }

    template<typename R> requires std::is_arithmetic_v<R>
    static constexpr TimeSpan fromMinutes(R v) noexcept { return std::chrono::duration<R, std::ratio<60>>(v); }

    template<typename R> requires std::is_arithmetic_v<R>
    static constexpr TimeSpan fromHours(R v) noexcept { return std::chrono::duration<R, std::ratio<3600>>(v); }

    constexpr Duration duration() const noexcept { return value_; }
    constexpr std::int64_t toNanoseconds() const noexcept { return value_.count(); }
    constexpr std::int64_t toMilliseconds() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(value_).count();
    }
    constexpr double toSeconds() const noexcept { return std::chrono::duration<double>(value_).count(); }

    constexpr bool isZero() const noexcept { return value_.count() == 0; }
    constexpr bool isNegative() const noexcept { return value_.count() < 0; }

    constexpr operator Duration() const noexcept { return value_; }

    constexpr auto operator<=>(const TimeSpan&) const noexcept = default;
    constexpr TimeSpan operator+(TimeSpan o) const noexcept { return TimeSpan(value_ + o.value_); }
    constexpr TimeSpan operator-(TimeSpan o) const noexcept { return TimeSpan(value_ - o.value_); }
    constexpr TimeSpan operator-() const noexcept { return TimeSpan(-value_); }

private:
    Duration value_ { 0 };
};

} // namespace taskpp
