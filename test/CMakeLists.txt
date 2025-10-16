# This is a standalone project file for the host-based unit tests.
cmake_minimum_required(VERSION 3.13)
project(protocol_unit_tests C)
set(CMAKE_C_STANDARD 11)

# --- Fetch the Unity Test Framework ---
include(FetchContent)
FetchContent_Declare(
    unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        v2.5.2
)
FetchContent_MakeAvailable(unity)

# --- Enable Testing ---
enable_testing()

# --- Define the Test Executable ---
add_executable(run_tests
    test_runner.c
    test_serial.c
    mocks/mock_pico_sdk.c
    ../src/serial.c # <-- Path back to the code under test
)

# --- Configure Include Directories ---
target_include_directories(run_tests PRIVATE
    ${unity_SOURCE_DIR}/src
    ../include # <-- Path back to the main include dir
    ./mocks        # <-- Path to the local mocks dir
)

# --- Link Unity ---
target_sources(run_tests PRIVATE ${unity_SOURCE_DIR}/src/unity.c)

# --- Add a compile definition for test builds ---
target_compile_definitions(run_tests PRIVATE UNIT_TEST)

# --- Register with CTest ---
add_test(NAME unit_tests COMMAND run_tests)