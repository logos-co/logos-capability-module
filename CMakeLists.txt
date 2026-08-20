cmake_minimum_required(VERSION 3.14)
project(CapabilityModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. Set LOGOS_MODULE_BUILDER_ROOT.")
endif()

# Universal module: `interface: "universal"` makes the builder derive the LIDL
# contract from src/capability_module_impl.h with
#   logos-cpp-generator --header-to-lidl
# then emit, into generated_code/, the Qt plugin glue with
#   logos-qt-host-generator --backend cdylib
# and the Qt-free C-ABI export wrapper (+ types header) with
#   logos-cpp-generator --lidl --backend cdylib
# (Not `--from-header`: that flag drives the `interface: "cdylib"` authoring
# path, not this one.) There is no hand-written plugin or interface header any
# more.
logos_module(
    NAME capability_module
    SOURCES
        src/capability_module_impl.h
        src/capability_module_impl.cpp
)
