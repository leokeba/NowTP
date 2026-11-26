# libFuzzer harnesses (test/fuzz/README.md): clang only, with ASan and
# UBSan, the library instrumented for coverage. Off by default
# (-DNOWTP_FUZZ=ON).
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "NOWTP_FUZZ needs clang (libFuzzer); set CMAKE_CXX_COMPILER=clang++")
endif()

set(NOWTP_FUZZ_FLAGS -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all
                     -fno-omit-frame-pointer -g)
target_compile_options(nowtp_core PRIVATE ${NOWTP_FUZZ_FLAGS})
# NowTP's malloc goes through the heap limit's hooks (test/heap_limit.h).
target_compile_definitions(nowtp_core PUBLIC NOWTP_HEAP_HOOKS)

foreach(name frames)
    add_executable(fuzz_${name} fuzz_${name}.cpp)
    target_link_libraries(fuzz_${name} PRIVATE nowtp_core)
    target_include_directories(fuzz_${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    set_target_properties(fuzz_${name} PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED ON)
    target_compile_options(fuzz_${name} PRIVATE -Wall -Wextra -Werror
                           -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
    target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined)
endforeach()
