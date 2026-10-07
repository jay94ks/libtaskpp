add_library(taskpp_tls
    src/Tls.cpp
)
add_library(taskpp::tls ALIAS taskpp_tls)

target_include_directories(taskpp_tls PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(taskpp_tls PUBLIC
    taskpp::socket taskpp::core taskpp::common Threads::Threads certpp::certpp)
target_compile_definitions(taskpp_tls PUBLIC TASKPP_WITH_TLS)

if (WIN32)
    target_link_libraries(taskpp_tls PUBLIC ws2_32)
endif()

if (MSVC)
    target_compile_options(taskpp_tls PRIVATE /W4)
else()
    target_compile_options(taskpp_tls PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (TASKPP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
