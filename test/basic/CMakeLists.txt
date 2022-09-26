set(CMAKE_C_COMPILER ${CMAKE_SOURCE_DIR}/tools/vcc)
set(CMAKE_CXX_COMPILER ${CMAKE_SOURCE_DIR}/tools/v++)

add_executable(pressure pressure.c)
add_executable(prime    prime.cpp)
add_executable(safe     safe.cpp)
add_executable(unsafe   unsafe.cpp)
add_executable(fakeoob  fakeoob.c)
