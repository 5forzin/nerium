cmake_minimum_required(VERSION 3.22)
project(androidlab_guest_keymint LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT ANDROID OR NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
  message(FATAL_ERROR "This service requires the Android x86_64 NDK toolchain")
endif()
foreach(INPUT GUEST_SOURCE_DIR KEYMASTER_SOURCE_DIR PLATFORM_BINDER_DIR GENERATED_AIDL_DIR)
  if(NOT ${INPUT})
    message(FATAL_ERROR "Missing ${INPUT}")
  endif()
  file(TO_CMAKE_PATH "${${INPUT}}" ${INPUT})
endforeach()
set(KM "${KEYMASTER_SOURCE_DIR}/keymaster")
file(GLOB_RECURSE AIDL_SOURCES CONFIGURE_DEPENDS "${GENERATED_AIDL_DIR}/src/*.cpp")
add_executable(androidlab-keymint-service service.cpp guest_channel.cpp
  "${GUEST_SOURCE_DIR}/guest/hals/keymint/remote/remote_keymaster.cpp"
  "${GUEST_SOURCE_DIR}/guest/hals/keymint/remote/remote_keymint_device.cpp"
  "${GUEST_SOURCE_DIR}/guest/hals/keymint/remote/remote_keymint_operation.cpp"
  "${GUEST_SOURCE_DIR}/guest/hals/keymint/remote/remote_shared_secret.cpp"
  "${GUEST_SOURCE_DIR}/guest/hals/keymint/remote/remote_secure_clock.cpp"
  "${GUEST_SOURCE_DIR}/keymaster/ng/KeyMintUtils.cpp"
  "${KM}/android_keymaster/android_keymaster_messages.cpp"
  "${KM}/android_keymaster/android_keymaster_utils.cpp"
  "${KM}/android_keymaster/authorization_set.cpp"
  "${KM}/android_keymaster/keymaster_tags.cpp"
  "${KM}/android_keymaster/logger.cpp"
  "${KM}/android_keymaster/serializable.cpp"
  ${AIDL_SOURCES})
target_include_directories(androidlab-keymint-service PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/compat"
  "${GUEST_SOURCE_DIR}" "${GUEST_SOURCE_DIR}/keymaster/ng/include"
  "${KM}/include" "${KEYMASTER_SOURCE_DIR}/hardware/include"
  "${GENERATED_AIDL_DIR}/include" "${PLATFORM_BINDER_DIR}/include")
target_compile_definitions(androidlab-keymint-service PRIVATE KEYMASTER_NAME_TAGS BINDER_STABILITY_SUPPORT __ANDROID_VENDOR__)
target_compile_options(androidlab-keymint-service PRIVATE -fno-rtti -Wall -Wextra)
target_link_libraries(androidlab-keymint-service PRIVATE "${PLATFORM_BINDER_DIR}/libbinder_ndk.so" log)
target_link_options(androidlab-keymint-service PRIVATE "-Wl,-rpath-link,${PLATFORM_BINDER_DIR}")
