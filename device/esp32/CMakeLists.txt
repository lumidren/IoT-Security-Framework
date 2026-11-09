# IronMesh ESP32 firmware (ESP-IDF v5.3.x).
#   idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.dev" build
#   idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.hil" build
#   idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.prod" build
cmake_minimum_required(VERSION 3.16)

# version.txt: line 1 = semver, line 2 = version_code (monotonic; also the eFuse secure version)
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/version.txt" IM_VERSION_LINES)
list(GET IM_VERSION_LINES 0 IM_FW_VERSION)
list(GET IM_VERSION_LINES 1 IM_FW_VERSION_CODE)
set(PROJECT_VER "${IM_FW_VERSION}")

# host/ (Rust test harness) and tools/ are not part of the firmware build
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ironmesh_esp32)

idf_build_set_property(COMPILE_DEFINITIONS "IM_FW_VERSION=\"${IM_FW_VERSION}\"" APPEND)
idf_build_set_property(COMPILE_DEFINITIONS "IM_FW_VERSION_CODE=${IM_FW_VERSION_CODE}ULL" APPEND)
