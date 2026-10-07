add_library(taskpp_socket
    src/Dns.cpp
    src/Socket.cpp
    src/SocketAddress.cpp
    src/SocketStream.cpp
)
add_library(taskpp::socket ALIAS taskpp_socket)

target_include_directories(taskpp_socket PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(taskpp_socket PUBLIC taskpp::core taskpp::common Threads::Threads c-ares::cares_static)

if (WIN32)
    target_link_libraries(taskpp_socket PUBLIC ws2_32)
    # windows.h min/max macros break standard code (e.g. TimeSpan::max()).
    target_compile_definitions(taskpp_socket PUBLIC NOMINMAX)
endif()

if (MSVC)
    target_compile_options(taskpp_socket PRIVATE /W4)
else()
    target_compile_options(taskpp_socket PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (TASKPP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
