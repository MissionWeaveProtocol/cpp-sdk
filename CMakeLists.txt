cmake_minimum_required(VERSION 3.24)

project(
  missionweaveprotocol
  VERSION 0.1.0
  DESCRIPTION "Official C++ protocol SDK for MissionWeaveProtocol"
  HOMEPAGE_URL "https://github.com/MissionWeaveProtocol/cpp-sdk"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

if(PROJECT_IS_TOP_LEVEL)
  set(MISSIONWEAVEPROTOCOL_DEFAULT_BUILD_TESTS ON)
else()
  set(MISSIONWEAVEPROTOCOL_DEFAULT_BUILD_TESTS OFF)
endif()

option(MISSIONWEAVEPROTOCOL_BUILD_TESTS "Build the MissionWeaveProtocol SDK tests"
       ${MISSIONWEAVEPROTOCOL_DEFAULT_BUILD_TESTS})
option(MISSIONWEAVEPROTOCOL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

add_library(missionweaveprotocol_sdk src/bundle.cpp src/embedded_assets.cpp src/version.cpp)
add_library(MissionWeaveProtocol::sdk ALIAS missionweaveprotocol_sdk)

target_compile_features(missionweaveprotocol_sdk PUBLIC cxx_std_20)
target_include_directories(
  missionweaveprotocol_sdk
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(missionweaveprotocol_sdk PUBLIC OpenSSL::Crypto)

set_target_properties(
  missionweaveprotocol_sdk
  PROPERTIES CXX_EXTENSIONS OFF
             EXPORT_NAME sdk
             OUTPUT_NAME missionweaveprotocol
             VERSION ${PROJECT_VERSION}
             SOVERSION ${PROJECT_VERSION_MAJOR})

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(missionweaveprotocol_sdk PRIVATE -Wall -Wextra -Wpedantic)
  if(MISSIONWEAVEPROTOCOL_WARNINGS_AS_ERRORS)
    target_compile_options(missionweaveprotocol_sdk PRIVATE -Werror)
  endif()
elseif(MSVC)
  target_compile_options(missionweaveprotocol_sdk PRIVATE /W4)
  if(MISSIONWEAVEPROTOCOL_WARNINGS_AS_ERRORS)
    target_compile_options(missionweaveprotocol_sdk PRIVATE /WX)
  endif()
endif()

install(
  TARGETS missionweaveprotocol_sdk
  EXPORT missionweaveprotocolTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_package_config_file(
  cmake/missionweaveprotocolConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/missionweaveprotocolConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/missionweaveprotocol)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/missionweaveprotocolConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(
  EXPORT missionweaveprotocolTargets
  FILE missionweaveprotocolTargets.cmake
  NAMESPACE MissionWeaveProtocol::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/missionweaveprotocol)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/missionweaveprotocolConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/missionweaveprotocolConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/missionweaveprotocol)

if(MISSIONWEAVEPROTOCOL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
