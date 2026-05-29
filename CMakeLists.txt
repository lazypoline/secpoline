# this is definitely not the lowest supported version
cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# we kind of depend on assert actually asserting (sigh)
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

project(secpoline C CXX ASM)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/static/)



set(COMMON_COMPILE_OPTIONS -Wall -Wextra -ggdb -fPIC -fno-exceptions -march=native
    # -fcf-protection=full
)
set(OPTIMIZATION -O3 -flto)
set(SECPOLINE_OPTIONS ${COMMON_COMPILE_OPTIONS} ${OPTIMIZATION} -fPIE)
set(COMMON_LINK_OPTIONS ${OPTIMIZATION} -rdynamic -pie)

set_property(
    SOURCE 
        src/syscall_monitor/restore_selector_trampoline.asm 
        src/syscall_monitor/asm_syscall_hook.asm 
        src/syscall_monitor/asm_entry_points.asm
        src/syscall_monitor/asm_syscall.asm
        src/segfault_handler/signal_handler_entry.asm
    APPEND PROPERTY COMPILE_OPTIONS "-x" "assembler-with-cpp"
)

file(GLOB_RECURSE SECPOLINE_SOURCES CONFIGURE_DEPENDS
    src/syscall_monitor/*.cpp
    src/syscall_monitor/*.asm
    src/syscall_handlers/*.cpp
    src/syscall_handlers/*.asm
    src/secpoline.cpp
)

file(GLOB_RECURSE SEGFAULT_HANDLER_SOURCES CONFIGURE_DEPENDS
    src/segfault_handler/*.cpp
    src/segfault_handler/*.asm
)

add_custom_target(falco_plugin ALL COMMAND ${CMAKE_MAKE_PROGRAM} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/falco_shim/secpoline_plugin)

add_subdirectory(falco EXCLUDE_FROM_ALL)

add_library(falco_shim STATIC falco_shim/falco_shim.cpp)
target_link_libraries(falco_shim PRIVATE falco_application)

#creates secpoline
add_executable(secpoline ${SECPOLINE_SOURCES})
target_compile_options(secpoline PUBLIC ${SECPOLINE_OPTIONS})
target_link_options(secpoline PUBLIC ${COMMON_LINK_OPTIONS}  -lssl -lcrypto  -ldl -lpthread -laudit)
target_link_libraries(secpoline PRIVATE falco_shim)

target_include_directories(secpoline PUBLIC ${PROJECT_SOURCE_DIR}/src/include)
target_include_directories(secpoline PUBLIC ${PROJECT_SOURCE_DIR}/falco_shim/)

#creates libsegfault_handler.so
add_library(segfault_handler SHARED ${SEGFAULT_HANDLER_SOURCES})
target_compile_options(segfault_handler PUBLIC ${COMMON_COMPILE_OPTIONS} ${OPTIMIZATION})
target_link_options(segfault_handler PUBLIC ${OPTIMIZATION} -static-libstdc++ -static-libgcc)
target_include_directories(segfault_handler PUBLIC ${PROJECT_SOURCE_DIR}/src/include)

#creates libloader.so
add_subdirectory(src/secpoline_loader)



add_executable(main tests/main.cpp)
target_compile_options(main PUBLIC ${SECPOLINE_OPTIONS})
target_link_options(main PUBLIC ${COMMON_LINK_OPTIONS} -ldl)
target_link_libraries(main PUBLIC "-lpthread")


add_subdirectory(benchmarks/microbench)


add_subdirectory(tests/security_eval)

