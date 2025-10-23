# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico CACHE STRING "Board type")

cmake_minimum_required(VERSION 3.13)

option(BUILD_TESTS "Enable building the unit tests" OFF)

# Pull in SDK (must be before project)
include(pico_sdk_import.cmake)
include(pico_extras_import_optional.cmake)

project(pico_project_template C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if (PICO_SDK_VERSION_STRING VERSION_LESS "2.2.0")
    message(FATAL_ERROR "Raspberry Pi Pico SDK version 2.2.0 (or later) required. Your version is ${PICO_SDK_VERSION_STRING}")
endif()

# If you want debug output from USB (pass -DPICO_STDIO_USB=1) this ensures you don't lose any debug output while USB is set up
if (NOT DEFINED PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS)
    set(PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS 3000)
endif()

# Allow using the example keys, as this is the examples repository
if (NOT DEFINED PICO_ALLOW_EXAMPLE_KEYS)
    set(PICO_ALLOW_EXAMPLE_KEYS 1)
endif()

# FreeRTOS configuration (must be before pico_sdk_init)
add_library(freertos_config INTERFACE)
target_include_directories(freertos_config INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)

include(FetchContent)
FetchContent_Populate(freertos_kernel
    GIT_REPOSITORY     "https://github.com/FreeRTOS/FreeRTOS-Kernel.git"
    GIT_TAG            "V11.2.0"
)
set(FREERTOS_KERNEL_PATH "${CMAKE_CURRENT_BINARY_DIR}/freertos_kernel-src" CACHE STRING "FreeRTOS Location" FORCE)

# Initialize the SDK
pico_sdk_init()

# Add appropriate FreeRTOS port based on platform
if(PICO_PLATFORM STREQUAL "rp2040")
    add_subdirectory(${FREERTOS_KERNEL_PATH}/portable/ThirdParty/GCC/RP2040)
elseif(PICO_PLATFORM STREQUAL "rp2350-arm-s")
    add_subdirectory(${FREERTOS_KERNEL_PATH}/portable/ThirdParty/Community-Supported-Ports/GCC/RP2350_ARM_NTZ)
elseif(PICO_PLATFORM STREQUAL "rp2350-riscv")
    add_subdirectory(${FREERTOS_KERNEL_PATH}/portable/ThirdParty/Community-Supported-Ports/GCC/RP2350_RISC-V)
else()
    message(FATAL_ERROR "Unsupported PICO_PLATFORM: ${PICO_PLATFORM}")
endif()

# add cryptoauthlib
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

get_target_property(CRYPTOAUTHLIB_SOURCES cryptoauth SOURCES)

# Filter the list, EXCLUDING the Linux-specific HAL files
list(FILTER CRYPTOAUTHLIB_SOURCES EXCLUDE REGEX ".*hal_linux.c")
list(FILTER CRYPTOAUTHLIB_SOURCES EXCLUDE REGEX ".*hal_linux_i2c_userspace.c")

# Set the target's sources to our new, filtered list
set_target_properties(cryptoauth PROPERTIES SOURCES "${CRYPTOAUTHLIB_SOURCES}")


include(example_auto_set_url.cmake)

add_compile_options(-Wall
        -Wno-format          # int != int32_t as far as the compiler is concerned because gcc has int32_t as long int
        -Wno-unused-function # we have some for the docs that aren't called
        -O3 #optimize for SPEED
        )

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-maybe-uninitialized)
endif()

add_executable(pico_project_template
    src/main.c
    src/serial.c
    src/protocol.c
)
# Link to pico_stdlib
target_link_libraries(pico_project_template
    pico_stdlib
    hardware_i2c
    cryptoauth
    FreeRTOS-Kernel-Heap4
    freertos_config)

# Enable usb output, disable uart output
pico_enable_stdio_usb(pico_project_template 1)
pico_enable_stdio_uart(pico_project_template 0)

# Create map/bin/hex file etc.
pico_add_extra_outputs(pico_project_template)

# Add include directory
target_include_directories(pico_project_template 
    PUBLIC 
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${cryptoauthlib_SOURCE_DIR}/lib
    ${cryptoauthlib_SOURCE_DIR}/lib/hal
    ${cryptoauthlib_SOURCE_DIR}/lib/calib
)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()