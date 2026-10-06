#pragma once
// Private socket-module helper: network runtime init. Not installed.
//
// Every Winsock call needs WSAStartup first; POSIX needs nothing. All socket
// module .cpps route through `detail::ensureWsa()` so direct users of
// `SocketAddress`/`Dns` (resolution, formatting) can never hit
// WSANOTINITIALISED.
#include <taskpp/Config.hpp>

#if defined(TASKPP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <system_error>

namespace taskpp::detail {

struct WsaInit {
    WsaInit() {
        WSADATA data { };
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::system_error(::WSAGetLastError(), std::system_category(), "WSAStartup");
        }
    }
};

inline void ensureWsa() {
    static WsaInit init;
    (void) init;
}

} // namespace taskpp::detail

#else // POSIX

namespace taskpp::detail {

inline void ensureWsa() noexcept { }

} // namespace taskpp::detail

#endif
