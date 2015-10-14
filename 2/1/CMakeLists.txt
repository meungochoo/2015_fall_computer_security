cmake_minimum_required(VERSION 3.0)

project(CS_Project2)
set(TRACER_NAME mytrace)

set(CMAKE_BUILD_TYPE Debug)
set(EXECUTABLE_OUTPUT_PATH build)

add_definitions(-std=c++11)

find_package(Boost 1.55.0 REQUIRED COMPONENTS program_options)

set(INCLUDE_DIR include)
include_directories(INCLUDE_DIR)
include_directories(${Boost_INCLUDE_DIR})

set(SOURCE_DIR source)
set(SOURCE_LIST)
list(APPEND SOURCE_LIST ${SOURCE_DIR}/${TRACER_NAME}.cpp)

set(BUILD_DIR build)
add_executable(${TRACER_NAME}.out ${SOURCE_LIST})
add_executable(testee.out test/testee.cpp)

target_link_libraries(${TRACER_NAME}.out ${Boost_LIBRARIES})
