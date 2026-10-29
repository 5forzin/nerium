cmake_minimum_required(VERSION 3.22)
project(device_lab_platform_bootstrap C)
file(TO_CMAKE_PATH "${REZYGISK_SOURCE}" REZYGISK_SOURCE)

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "x86_64")
    message(FATAL_ERROR "This prototype supports the dedicated x86_64 Android AVD only")
endif()
if(NOT EXISTS "${REZYGISK_SOURCE}/zygiskd/src/main.c")
    message(FATAL_ERROR "Provide the pinned ReZygisk source with initialized submodules")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_definitions(_GNU_SOURCE ANDROID
    MIN_APATCH_VERSION=10655 MIN_KSU_VERSION=10940 MIN_MAGISK_VERSION=26402
    ZKSU_VERSION="device-lab-platform-prototype")
add_compile_options(-O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function)

set(loader "${REZYGISK_SOURCE}/loader/src")
set(daemon "${REZYGISK_SOURCE}/zygiskd/src")
set(plti "${loader}/external/plti")
set(cso "${loader}/external/csoloader")

add_library(platform_plti STATIC
    "${plti}/src/plti.c" "${plti}/src/elf_util.c" "${plti}/src/fd_utils.c")
target_include_directories(platform_plti PUBLIC "${plti}/src")

add_library(platform_csoloader STATIC
    "${cso}/src/backtrace-support.c" "${cso}/src/carray.c"
    "${cso}/src/csoloader.c" "${cso}/src/elf_util.c"
    "${cso}/src/linker.c" "${cso}/src/sleb128.c")
target_include_directories(platform_csoloader PUBLIC "${cso}/include")
target_compile_options(platform_csoloader PRIVATE -Wno-int-conversion)

add_library(platform_common STATIC
    "${loader}/common/daemon.c" "${loader}/common/elf_util.c"
    "${loader}/common/misc.c" "${loader}/common/socket_utils.c")
target_include_directories(platform_common PUBLIC "${loader}/include")

add_library(zygisk SHARED
    "${loader}/injector/cpp_strings.c" "${loader}/injector/entry.c"
    "${loader}/injector/hook.c" "${loader}/injector/ptrace_clear.c")
target_include_directories(zygisk PRIVATE "${loader}/include")
option(DEVICE_LAB_APP_DEBUG_LOGS "Enable verbose framework traces inside application processes" OFF)
if(NOT DEVICE_LAB_APP_DEBUG_LOGS)
    target_compile_definitions(zygisk PRIVATE NDEBUG)
    target_compile_definitions(platform_common PRIVATE NDEBUG)
endif()
target_compile_options(zygisk PRIVATE -fno-stack-protector -fomit-frame-pointer)
# The upstream remote loader calls its explicit entry point without CRT startup.
target_link_options(zygisk PRIVATE -nostartfiles -Wl,--no-undefined -Wl,--no-rosegment)
target_link_libraries(zygisk PRIVATE platform_common platform_plti platform_csoloader log dl m)

add_executable(zygisk-ptrace64
    "${loader}/ptracer/main.c" "${loader}/ptracer/monitor.c"
    "${loader}/ptracer/ptracer.c" "${loader}/ptracer/remote_csoloader.c"
    "${loader}/ptracer/utils.c")
target_include_directories(zygisk-ptrace64 PRIVATE "${loader}/include")
target_link_libraries(zygisk-ptrace64 PRIVATE platform_common log dl m)

add_executable(zygiskd64
    "${daemon}/root_impl/apatch.c" "${daemon}/root_impl/common.c"
    "${daemon}/root_impl/kernelsu.c" "${daemon}/root_impl/magisk.c"
    "${daemon}/companion.c" "${daemon}/main.c" "${daemon}/utils.c" "${daemon}/zygiskd.c")
target_include_directories(zygiskd64 PRIVATE "${daemon}" "${daemon}/root_impl")
target_link_libraries(zygiskd64 PRIVATE log dl)
