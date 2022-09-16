INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/src/runtime/include")

add_library(runtime STATIC
    lib.c
)
