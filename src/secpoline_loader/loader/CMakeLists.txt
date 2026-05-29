file(GLOB_RECURSE loader_sources *.c)
set(CMAKE_BUILD_TYPE Debug)

set(BASE_LIBRARY_PATH ${CMAKE_BINARY_DIR}/tests/shared)
configure_file(basepath.h.in basepath.h @ONLY ESCAPE_QUOTES)
set_property(SOURCE asm_load_secpoline.asm APPEND PROPERTY COMPILE_OPTIONS "-x" "assembler-with-cpp")


add_library(loader SHARED ${loader_sources} asm_load_secpoline.asm)
target_link_options(loader PRIVATE -Wl,-soname=libloader.so -Wl,-z,now -Wl,-Bstatic -Wl,--dynamic-list=${CMAKE_CURRENT_SOURCE_DIR}/dynamic-list.txt)
target_link_libraries(loader PRIVATE static_pie_crt_object crt_headers)
target_link_libraries(loader INTERFACE $<TARGET_FILE:loader>)
target_include_directories(loader PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(loader PRIVATE ${CMAKE_SOURCE_DIR}/src/include)


set(LOADER_OBJECT_PATH ${CMAKE_CURRENT_BINARY_DIR}/libloader.so PARENT_SCOPE)

add_library(dynamic_loader INTERFACE)
target_link_options(dynamic_loader INTERFACE -Wl,-dynamic-linker,$<TARGET_FILE:loader>)
add_dependencies(dynamic_loader loader)
