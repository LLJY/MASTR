# CMake build configuration for the Pico ATECC608A project.
#
# This version corrects the cryptoauthlib target name to 'cryptoauth',
# which is the name defined by the library's own build scripts.
#

cmake_minimum_required(VERSION 3.13)
set(PICO_BOARD pico CACHE STRING "Board type")

# Pull in the Pico SDK (must be done before the project() call)
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(pico_atecc608_app C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Initialize the Pico SDK
pico_sdk_init()


include(FetchContent)

# Set options for cryptoauthlib BEFORE it is fetched.
set(UNIX FALSE) # Prevent cryptoauthlib from thinking we are on linux
set(ATCA_HAL_I2C ON CACHE BOOL "Enable the I2C HAL infrastructure (which we will override)")
set(ATCA_HAL_SPI OFF CACHE BOOL "Disable default SPI HAL")
set(ATCA_HAL_SWI OFF CACHE BOOL "Disable default SWI HAL")
set(ATCA_HAL_UART OFF CACHE BOOL "Disable default UART HAL")
set(ATCA_HAL_KIT_HID OFF CACHE BOOL "Disable default Kit HID HAL")
set(ATCA_HAL_KIT_CDC OFF CACHE BOOL "Disable default Kit CDC HAL")
set(ATCA_HAL_CUSTOM OFF CACHE BOOL "Disable the 'custom' HAL mechanism")
set(ATCA_TNGTLS_SUPPORT OFF CACHE BOOL "Disable TNGTLS support")
set(ATCA_OPENSSL_SUPPORT OFF CACHE BOOL "Disable OpenSSL support")
set(ATCA_BUILD_TESTS OFF CACHE BOOL "Disable building tests")

FetchContent_Declare(
    cryptoauthlib
    GIT_REPOSITORY https://github.com/MicrochipTech/cryptoauthlib.git
    GIT_TAG        v3.7.9
)
FetchContent_MakeAvailable(cryptoauthlib)

# --- THE KEY FIX ---
# Use the correct target name 'cryptoauth' as defined by the library.
get_target_property(CRYPTOAUTHLIB_SOURCES cryptoauth SOURCES)

# Filter the list, EXCLUDING the Linux-specific HAL files
list(FILTER CRYPTOAUTHLIB_SOURCES EXCLUDE REGEX ".*hal_linux.c")
list(FILTER CRYPTOAUTHLIB_SOURCES EXCLUDE REGEX ".*hal_linux_i2c_userspace.c")

# Set the target's sources to our new, filtered list
set_target_properties(cryptoauth PROPERTIES SOURCES "${CRYPTOAUTHLIB_SOURCES}")

# CRITICAL: Add preprocessor defines to the cryptoauth library itself
target_compile_definitions(cryptoauth PUBLIC
    ATCA_HAL_I2C
    ATCA_ATECC608A_SUPPORT
    ATCA_CA_SUPPORT
)

# Main simple test
add_executable(${PROJECT_NAME}
    src/main.c
    src/hal/hal_pico_i2c.c
)

# Link against the correct 'cryptoauth' target name
target_link_libraries(${PROJECT_NAME}
    pico_stdlib
    hardware_i2c
    cryptoauth
)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${cryptoauthlib_SOURCE_DIR}/lib
    ${cryptoauthlib_SOURCE_DIR}/lib/hal
    ${cryptoauthlib_SOURCE_DIR}/lib/calib
)

# Add compile definitions for CryptoAuthLib
target_compile_definitions(${PROJECT_NAME} PUBLIC
    ATCA_HAL_I2C
    ATCA_ATECC608A_SUPPORT
    ATCA_CA_SUPPORT
    ATCA_NO_HEAP  # Use stack allocation instead of heap
)

pico_add_extra_outputs(${PROJECT_NAME})
pico_enable_stdio_usb(${PROJECT_NAME} 1)
pico_enable_stdio_uart(${PROJECT_NAME} 0)

# Read-only configuration analyzer (SAFE - no writes)
add_executable(pico_atecc608_analyze
    src/analyze_config.c
    src/hal/hal_pico_i2c.c
)

target_link_libraries(pico_atecc608_analyze
    pico_stdlib
    hardware_i2c
    cryptoauth
)

target_include_directories(pico_atecc608_analyze PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${cryptoauthlib_SOURCE_DIR}/lib
    ${cryptoauthlib_SOURCE_DIR}/lib/hal
    ${cryptoauthlib_SOURCE_DIR}/lib/calib
)

target_compile_definitions(pico_atecc608_analyze PUBLIC
    ATCA_HAL_I2C
    ATCA_ATECC608A_SUPPORT
    ATCA_CA_SUPPORT
    ATCA_NO_HEAP
)

pico_add_extra_outputs(pico_atecc608_analyze)
pico_enable_stdio_usb(pico_atecc608_analyze 1)
pico_enable_stdio_uart(pico_atecc608_analyze 0)

# MASTR Protocol Test - Tests ALL required functions
add_executable(pico_atecc608_mastr_test
    src/mastr_test.c
    src/hal/hal_pico_i2c.c
)

target_link_libraries(pico_atecc608_mastr_test
    pico_stdlib
    hardware_i2c
    cryptoauth
)

target_include_directories(pico_atecc608_mastr_test PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${cryptoauthlib_SOURCE_DIR}/lib
    ${cryptoauthlib_SOURCE_DIR}/lib/hal
    ${cryptoauthlib_SOURCE_DIR}/lib/calib
)

target_compile_definitions(pico_atecc608_mastr_test PUBLIC
    ATCA_HAL_I2C
    ATCA_ATECC608A_SUPPORT
    ATCA_CA_SUPPORT
    ATCA_NO_HEAP
)

pico_add_extra_outputs(pico_atecc608_mastr_test)
pico_enable_stdio_usb(pico_atecc608_mastr_test 1)
pico_enable_stdio_uart(pico_atecc608_mastr_test 0)

