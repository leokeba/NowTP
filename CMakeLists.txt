# ESP-IDF component when built by idf.py, host library + tests otherwise.
if(ESP_PLATFORM)
    idf_component_register(
        SRCS "src/nowtp/wire.cpp" "src/nowtp/engine.cpp" "src/nowtp/espnow_transport.cpp"
        INCLUDE_DIRS "src"
        REQUIRES esp_wifi esp_ringbuf esp_timer)
    return()
endif()

cmake_minimum_required(VERSION 3.16)
project(nowtp CXX)

option(NOWTP_BUILD_TESTS "Build host-side tests" ON)
option(NOWTP_SANITIZE "Build tests with ASan/UBSan" ON)

# The core stays C++11 so it builds on Arduino-ESP32 2.x.
add_library(nowtp_core src/nowtp/wire.cpp src/nowtp/engine.cpp)
target_include_directories(nowtp_core PUBLIC src)
set_target_properties(nowtp_core PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_compile_options(nowtp_core PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror)

if(NOWTP_BUILD_TESTS)
    enable_testing()
    add_executable(nowtp_tests test/test_main.cpp)
    target_link_libraries(nowtp_tests PRIVATE nowtp_core)
    set_target_properties(nowtp_tests PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED ON)
    target_compile_options(nowtp_tests PRIVATE -Wall -Wextra)
    if(NOWTP_SANITIZE)
        foreach(t nowtp_core nowtp_tests)
            target_compile_options(${t} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
            target_link_options(${t} PRIVATE -fsanitize=address,undefined)
        endforeach()
    endif()
    add_test(NAME nowtp_tests COMMAND nowtp_tests)
endif()
