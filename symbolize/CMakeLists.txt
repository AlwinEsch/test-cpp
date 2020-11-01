cmake_minimum_required(VERSION 3.5)
project(symbolize)

set(SOURCES config.h
            demangle.cc
            demangle.h
            glog/logging.h
            glog/raw_logging.h
            symbolize.cc
            symbolize.h
            utilities.h)

set(CMAKE_POSITION_INDEPENDENT_CODE 1)
add_library(symbolize STATIC ${SOURCES})
