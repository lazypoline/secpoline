
set_property(
    SOURCE 
        bench_syscall.asm
    APPEND PROPERTY COMPILE_OPTIONS "-x" "assembler-with-cpp"
)

add_executable(bench bench.cpp bench_syscall.asm)
target_compile_options(main PUBLIC ${secpoline_OPTIONS})
target_link_options(main PUBLIC ${COMMON_LINK_OPTIONS})
