cmake_minimum_required(VERSION 3.0)

project(CS_Project2)
set(TRACER_NAME mytrace)

set(CMAKE_BUILD_TYPE Debug)
set(EXECUTABLE_OUTPUT_PATH build)

add_definitions(-std=c++11)

find_package(Boost 1.55.0 REQUIRED COMPONENTS program_options)

set(INCLUDE_DIR include)
include_directories(${INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIR})

set(SOURCE_DIR source)
set(SOURCE_LIST)
list(APPEND SOURCE_LIST ${SOURCE_DIR}/${TRACER_NAME}.cpp)
list(APPEND SOURCE_LIST ${SOURCE_DIR}/Tracer.cpp)

add_executable(${TRACER_NAME} ${SOURCE_LIST})
add_executable(testee test/testee.cpp)

target_link_libraries(${TRACER_NAME} ${Boost_LIBRARIES})
