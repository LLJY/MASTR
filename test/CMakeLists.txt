# This is a standalone project file for the host-based unit tests.
cmake_minimum_required(VERSION 3.13)
project(protocol_unit_tests C)
set(CMAKE_C_STANDARD 11)

# Code coverage support (optional, controlled by ENABLE_COVERAGE flag)
option(ENABLE_COVERAGE "Enable code coverage measurement" OFF)
if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    message(STATUS "Code coverage enabled - use 'make coverage' to generate reports")
endif()

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
    # Test runner and common utilities
    test_runner.c
    test_common.c

    # Existing test suites (55 tests)
    test_serial.c
    test_protocol.c
    test_session.c
    test_nonce.c
    test_integrity.c

    # New test suites (41 tests) - Phase 1
    test_crypto.c
    test_provisioning.c
    test_api.c

    # HTTP server test suite (26 tests)
    test_http_server.c

    # WiFi AP test suite (30 tests)
    test_wifi_ap.c

    # Mocks (hardware abstraction only)
    mocks/mock_pico_sdk.c
    mocks/mock_crypto.c
    mocks/mock_time.c
    mocks/mock_atca.c
    mocks/mock_lwip.c
    mocks/mock_wifi.c

    # Source files under test (including real crypto.c!)
    ../src/serial.c
    ../src/protocol.c
    ../src/crypto.c
    ../src/net/http/http_server.c
    ../src/net/wifi_ap.c
    ../src/net/ap/ap_manager.c
    # Note: API endpoints are tested via test_api.c
)

# --- Configure Include Directories ---
target_include_directories(run_tests PRIVATE
    ${unity_SOURCE_DIR}/src
    ../include
    ./mocks
    ./mocks/lwip
)

# --- Link Libraries ---
target_sources(run_tests PRIVATE ${unity_SOURCE_DIR}/src/unity.c)

# Link mbedtls for real cryptographic implementations
find_package(MbedTLS REQUIRED)
if(MbedTLS_FOUND)
    target_link_libraries(run_tests PRIVATE
        MbedTLS::mbedcrypto
    )
    message(STATUS "mbedTLS found - linking mbedcrypto library")
else()
    # Fallback: Try linking directly if find_package fails
    target_link_libraries(run_tests PRIVATE mbedcrypto)
    message(STATUS "mbedTLS package not found - attempting direct library link")
endif()

# --- Add a compile definition for test builds ---
target_compile_definitions(run_tests PRIVATE UNIT_TEST)

# --- Register with CTest ---
add_test(NAME unit_tests COMMAND run_tests)

# --- Code Coverage Target (requires lcov installed) ---
if(ENABLE_COVERAGE)
    add_custom_target(coverage
        COMMAND ${CMAKE_COMMAND} -E echo "Running tests with coverage..."
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/run_tests
        COMMAND ${CMAKE_COMMAND} -E echo "Generating coverage report..."
        COMMAND lcov --capture --directory . --output-file coverage.info --ignore-errors inconsistent
        COMMAND lcov --remove coverage.info '*/unity/*' '*/mocks/*' '*/test_*.c' --output-file coverage_filtered.info --ignore-errors unused
        COMMAND genhtml coverage_filtered.info --output-directory coverage_html
        COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated in coverage_html/index.html"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS run_tests
        COMMENT "Generating code coverage report"
    )
endif()