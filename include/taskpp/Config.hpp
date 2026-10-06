#pragma once

// Platform detection shared by every libtaskpp module.

#if defined(_WIN32)
#   define TASKPP_PLATFORM_WINDOWS 1
#elif defined(__linux__)
#   define TASKPP_PLATFORM_LINUX 1
#   define TASKPP_PLATFORM_POSIX 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__unix__)
#   define TASKPP_PLATFORM_POSIX 1
#endif

#if __cplusplus < 202002L && (!defined(_MSVC_LANG) || _MSVC_LANG < 202002L)
#   error "libtaskpp requires C++20 or above."
#endif
