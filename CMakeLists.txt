cmake_minimum_required(VERSION 3.4)
project(TestApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(lib/symbolize)

add_executable(TestApp xbmc/AppParamParser.cpp
                       xbmc/AppParamParser.h
                       xbmc/debug/StackTrace.cpp
                       xbmc/debug/StackTrace.h
                       xbmc/debug/StackTracePosix.cpp
                       xbmc/platform/posix/main.cpp
                       xbmc/platform/xbmc.cpp
                       xbmc/platform/xbmc.h
                       xbmc/utils/StringUtils.h
                       xbmc/utils/Utils.h
                       xbmc/utils/log.h
                       xbmc/system.h)

target_link_libraries(TestApp pthread dl symbolize)
target_include_directories(TestApp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/xbmc
                                           ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_compile_definitions(TestApp PRIVATE -DTARGET_LINUX=1 -DTARGET_POSIX=1 -DARCH_CPU_64_BITS=1 -DARCH_CPU_X86_FAMILY=1 -D_DEBUG)



