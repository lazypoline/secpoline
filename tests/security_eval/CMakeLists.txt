cmake_minimum_required(VERSION 3.15)

project(security_eval C CXX)

set(COMMON_COMPILE_OPTIONS -Wall -Wextra -ggdb -fPIC -fno-exceptions -march=native)
set(OPTIMIZATION -O0 -flto)

add_compile_options(${COMMON_COMPILE_OPTIONS} ${OPTIMIZATION})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/output/security_eval)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/output/security_eval)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/output/security_eval)



set(LIBATTACK "${CMAKE_CURRENT_SOURCE_DIR}/_libattack.cpp")

file(GLOB_RECURSE CPP_SOURCES
    process_vm.cpp
    proc_mem.cpp
    sigreturn.cpp
    sigreturn_race.cpp
    mremap.cpp
    signal_delivery.cpp
    seccomp.cpp
    scanning_race.cpp
    mprotect32.cpp
    mutable_mappings.cpp
    shared_memory.cpp
    forged_signal.cpp
    munmap.cpp
    cross_page.cpp
    syscall_miss.cpp
    map_race.cpp
    rseq.cpp
    breakpoint_remap.cpp
    thread_breakpoint.cpp
)

foreach(SRC ${CPP_SOURCES})
    get_filename_component(TARGET_NAME ${SRC} NAME_WE)

    add_executable(${TARGET_NAME} ${SRC} ${LIBATTACK})
    target_compile_options(${TARGET_NAME} PUBLIC ${secpoline_OPTIONS})
    target_link_options(${TARGET_NAME} PUBLIC ${COMMON_LINK_OPTIONS} -pthread -lrt)
    target_link_options(${TARGET_NAME} PRIVATE "-Wl,--dynamic-linker=${CMAKE_SOURCE_DIR}/output/libloader.so")
endforeach()