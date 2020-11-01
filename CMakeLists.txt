cmake_minimum_required(VERSION 3.4)
project(TestApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(symbolize)


add_executable(TestApp main.cpp
                      debug/stack_trace.cc
                        debug/stack_trace_posix.cc)
target_link_libraries(TestApp pthread dl symbolize)
target_include_directories(TestApp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(TestApp PRIVATE -DTARGET_LINUX=1 -DTARGET_POSIX=1 -DARCH_CPU_64_BITS=1 -DARCH_CPU_X86_FAMILY=1)



