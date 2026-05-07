cmake_minimum_required(VERSION 3.14)
project(CapabilityModuleTests LANGUAGES CXX)

include(LogosTest)

logos_test(
    NAME capability_module_tests
    MODULE_SOURCES
        ../src/capability_module_impl.cpp
    TEST_SOURCES
        main.cpp
        test_capability_module.cpp
    GENERATED_SOURCES
        ../generated_code/logos_provider_dispatch.cpp
    GENERATED_DIR
        ../generated_code
)
