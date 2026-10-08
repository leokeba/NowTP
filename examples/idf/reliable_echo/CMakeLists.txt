cmake_minimum_required(VERSION 3.16)
# Use this checkout of NowTP as a component.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../..")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(nowtp_reliable_echo)
