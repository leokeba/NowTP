# ESP-IDF component when built by idf.py, host library + tests otherwise.
if(ESP_PLATFORM)
    idf_component_register(
        SRCS "src/nowtp/wire.cpp" "src/nowtp/engine.cpp" "src/nowtp/engine_tx.cpp" "src/nowtp/engine_rx.cpp" "src/nowtp/discovery.cpp" "src/nowtp/radio.cpp" "src/nowtp/diagnostics.cpp"
             "src/nowtp/crypto.cpp" "src/nowtp/security.cpp" "src/nowtp/channel.cpp" "src/nowtp/timesync.cpp" "src/nowtp/stream.cpp"
             "src/nowtp/peer_table.cpp" "src/nowtp/link_monitor.cpp" "src/nowtp/duplicate_filter.cpp"
             "src/nowtp/credit_book.cpp"
             "src/nowtp/espnow_transport.cpp"
        INCLUDE_DIRS "src"
        REQUIRES esp_wifi esp_ringbuf esp_timer esp_event nvs_flash mbedtls)
    return()
endif()

cmake_minimum_required(VERSION 3.16)
project(nowtp CXX)

option(NOWTP_BUILD_TESTS "Build host-side tests" ON)
option(NOWTP_SANITIZE "Build tests with ASan/UBSan" ON)

# The core stays C++11 so it builds on Arduino-ESP32 2.x.
add_library(nowtp_core src/nowtp/wire.cpp src/nowtp/engine.cpp src/nowtp/engine_tx.cpp src/nowtp/engine_rx.cpp src/nowtp/discovery.cpp src/nowtp/radio.cpp src/nowtp/diagnostics.cpp
            src/nowtp/crypto.cpp src/nowtp/security.cpp src/nowtp/channel.cpp src/nowtp/timesync.cpp src/nowtp/stream.cpp
            src/nowtp/peer_table.cpp src/nowtp/link_monitor.cpp src/nowtp/duplicate_filter.cpp
            src/nowtp/credit_book.cpp)
target_include_directories(nowtp_core PUBLIC src)
set_target_properties(nowtp_core PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_compile_options(nowtp_core PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror)

if(NOWTP_BUILD_TESTS)
    # Lets the tests count NowTP's malloc() and make it fail (test/heap_limit.h).
    target_compile_definitions(nowtp_core PUBLIC NOWTP_HEAP_HOOKS)
    enable_testing()
    find_package(Threads REQUIRED)
    add_executable(nowtp_tests test/test_main.cpp)
    target_link_libraries(nowtp_tests PRIVATE nowtp_core Threads::Threads ${CMAKE_DL_LIBS})
    set_target_properties(nowtp_tests PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED ON)
    target_compile_options(nowtp_tests PRIVATE -Wall -Wextra)
    if(NOWTP_SANITIZE)
        foreach(t nowtp_core nowtp_tests)
            target_compile_options(${t} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
            target_link_options(${t} PRIVATE -fsanitize=address,undefined)
        endforeach()
    endif()
    add_test(NAME nowtp_tests COMMAND nowtp_tests)
    # Again, ticking only what is due, as a poller sleeping on pollDelayMs() does.
    add_test(NAME nowtp_tests_sparse COMMAND nowtp_tests)
    set_tests_properties(nowtp_tests_sparse PROPERTIES ENVIRONMENT NOWTP_SPARSE_TICKS=1)
    # Across the ms clock's sign change (24.8 days of uptime) and its wrap (49.7 days).
    add_test(NAME nowtp_tests_late COMMAND nowtp_tests)
    set_tests_properties(nowtp_tests_late PROPERTIES ENVIRONMENT NOWTP_CLOCK_START=0x7FFFF000)
    add_test(NAME nowtp_tests_wrap COMMAND nowtp_tests)
    set_tests_properties(nowtp_tests_wrap PROPERTIES ENVIRONMENT "NOWTP_CLOCK_START=0xFFFFF000;NOWTP_SPARSE_TICKS=1")
endif()
