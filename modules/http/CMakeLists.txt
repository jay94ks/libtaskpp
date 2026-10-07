add_library(taskpp_http
    src/Body.cpp
    src/Form.cpp
    src/H1.cpp
    src/H2.cpp
    src/Hpack.cpp
    src/HttpMessage.cpp
    src/Json.cpp
)
add_library(taskpp::http ALIAS taskpp_http)

target_include_directories(taskpp_http PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(taskpp_http PUBLIC
    taskpp::tls taskpp::socket taskpp::core taskpp::common Threads::Threads)
target_compile_definitions(taskpp_http PUBLIC TASKPP_WITH_HTTP)

if (WIN32)
    target_link_libraries(taskpp_http PUBLIC ws2_32)
endif()

if (MSVC)
    target_compile_options(taskpp_http PRIVATE /W4)
else()
    target_compile_options(taskpp_http PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (TASKPP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
