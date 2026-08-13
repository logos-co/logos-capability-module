cmake_minimum_required(VERSION 3.14)
project(CapabilityModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. Set LOGOS_MODULE_BUILDER_ROOT.")
endif()

# Universal module: `interface: "universal"` makes the builder run
# logos-cpp-generator --from-header on src/capability_module_impl.h and emit the
# Qt plugin glue, the dispatch and the C-ABI exports into generated_code/.
# There is no hand-written plugin or interface header any more.
logos_module(
    NAME capability_module
    SOURCES
        src/capability_module_impl.h
        src/capability_module_impl.cpp
)
