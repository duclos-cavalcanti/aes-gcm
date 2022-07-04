cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

project(foo)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set (DEBUG_FLAGS
    "-g")

set (OPT_FLAGS
    "-O0")

set (WARN_FLAGS
    "-Wall")

set(GCC_COMPILE_FLAGS 
    "${DEBUG_FLAGS} ${OPT_FLAGS} ${WARN_FLAGS}")

set(CMAKE_C_FLAGS 
    "${CMAKE_C_FLAGS} ${GCC_COMPILE_FLAGS}")

file(GLOB SOURCES "src/*.c")
file(GLOB LIB_SOURCES "lib/*.c")

set(PROJECT_SOURCES
    ${SOURCES} 
    ${LIB_SOURCES}
)

include_directories(include)

set(PROJECT_INCLUDES
    ${PROJECT_SOURCE_DIR}/include/
    ${PROJECT_SOURCE_DIR}/lib/include
)

add_executable(bar ${PROJECT_SOURCES})

include(debug)
include(clean)
