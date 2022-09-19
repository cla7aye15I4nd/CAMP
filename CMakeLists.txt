cmake_minimum_required(VERSION 3.10)
project(violet-pass)

if ( _cpp_17_flag_supported )
    set( CMAKE_CXX_STANDARD 17 )
endif()

find_package(LLVM REQUIRED CONFIG)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(${LLVM_INCLUDE_DIRS})

add_subdirectory(src/compiler_pass)
add_subdirectory(src/runtime)
