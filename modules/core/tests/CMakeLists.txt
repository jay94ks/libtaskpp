set(TASKPP_CORE_TESTS
    TaskTests
    WorkerTests
    CancellerTests
    AsyncQueueTests
    WhenAllTests
    AsyncMutexTests
    ChannelTests
    TimerTests
)

if (UNIX OR WIN32)
    list(APPEND TASKPP_CORE_TESTS MonitorTests)
endif()

foreach (name IN LISTS TASKPP_CORE_TESTS)
    add_executable(core_${name} ${name}.cpp)
    target_link_libraries(core_${name} PRIVATE taskpp::core)
    add_test(NAME core.${name} COMMAND core_${name})
    set_tests_properties(core.${name} PROPERTIES TIMEOUT 60)
endforeach()
