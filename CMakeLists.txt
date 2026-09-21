cmake_minimum_required(VERSION 3.20)

project(SwitchFailoverFabric
        VERSION 1.0.0
        DESCRIPTION "Switch-level failure fencing and authoritative reconstruction planning runtime"
        HOMEPAGE_URL "https://github.com/summonlabs/Switch-Failover-Fabric"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(SFF_BUILD_TESTS     "Build the Switch Failover Fabric verification suites" ON)
option(SFF_BUILD_TOOLS     "Build sffctl and the proof drivers"                  ON)
option(SFF_BUILD_EXAMPLES  "Build the example programs"                         ON)
option(SFF_WARNINGS_AS_ERRORS "Treat compiler warnings as errors"               OFF)
option(SFF_ENABLE_ASAN     "Build with AddressSanitizer"                        OFF)
option(SFF_ENABLE_UBSAN    "Build with UndefinedBehaviorSanitizer"              OFF)
option(SFF_STRICT_WARNINGS "Enable the full strict warning set"                 ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# ---------------------------------------------------------------------------
# Warnings / sanitizer interface
# ---------------------------------------------------------------------------
add_library(sff_build_options INTERFACE)
add_library(SwitchFailoverFabric::build_options ALIAS sff_build_options)

if(MSVC)
  target_compile_options(sff_build_options INTERFACE
    /Zc:__cplusplus /Zc:preprocessor /permissive- /utf-8 /EHsc /bigobj)
  if(SFF_STRICT_WARNINGS)
    target_compile_options(sff_build_options INTERFACE /W4)
  endif()
  if(SFF_WARNINGS_AS_ERRORS)
    target_compile_options(sff_build_options INTERFACE /WX)
  endif()
  target_compile_definitions(sff_build_options INTERFACE
    _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(sff_build_options INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(SFF_WARNINGS_AS_ERRORS)
    target_compile_options(sff_build_options INTERFACE -Werror)
  endif()
endif()

if(SFF_ENABLE_ASAN)
  if(MSVC)
    target_compile_options(sff_build_options INTERFACE /fsanitize=address)
  else()
    target_compile_options(sff_build_options INTERFACE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(sff_build_options INTERFACE -fsanitize=address)
  endif()
endif()

if(SFF_ENABLE_UBSAN)
  if(MSVC)
    message(STATUS "SFF: UBSan is not available on this toolchain (MSVC); SFF_ENABLE_UBSAN ignored")
  else()
    target_compile_options(sff_build_options INTERFACE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(sff_build_options INTERFACE -fsanitize=undefined)
  endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(SFF_SOURCES
  src/core/outcome.cpp
  src/core/version.cpp
  src/core/identity.cpp
  src/core/limits.cpp
  src/core/clock.cpp
  src/core/log.cpp
  src/codec/bytes.cpp
  src/codec/integrity.cpp
  src/model/generation.cpp
  src/model/switch.cpp
  src/model/topology.cpp
  src/model/evidence.cpp
  src/model/authority.cpp
  src/model/decision.cpp
  src/plan/plan.cpp
  src/plan/planning_core.cpp
  src/plan/planner.cpp
  src/plan/validator.cpp
  src/plan/reference_solver.cpp
  src/persist/records.cpp
  src/persist/store.cpp
  src/runtime/policy.cpp
  src/runtime/session.cpp
  src/runtime/coordinator.cpp
  src/runtime/failover.cpp
  src/transport/frame.cpp
  src/transport/socket.cpp
  src/transport/server.cpp
  src/transport/client.cpp)

add_library(sff ${SFF_SOURCES})
add_library(SwitchFailoverFabric::sff ALIAS sff)

target_include_directories(sff
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Build options are a build-tree concern only: they must not appear in the installed package.
target_link_libraries(sff PRIVATE $<BUILD_INTERFACE:sff_build_options>)
target_compile_definitions(sff PRIVATE SFF_BUILDING_LIBRARY)
target_compile_features(sff PUBLIC cxx_std_20)
set_target_properties(sff PROPERTIES
  OUTPUT_NAME "sff"
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  DEBUG_POSTFIX "d")

if(WIN32)
  target_link_libraries(sff PUBLIC ws2_32)
endif()

if(BUILD_SHARED_LIBS)
  target_compile_definitions(sff PUBLIC SFF_SHARED)
endif()

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
if(SFF_BUILD_TOOLS)
  add_subdirectory(tools)
endif()
if(SFF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(SFF_BUILD_TESTS AND BUILD_TESTING)
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install / package
# ---------------------------------------------------------------------------
install(TARGETS sff
  EXPORT SwitchFailoverFabricTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/sff
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT SwitchFailoverFabricTargets
  FILE SwitchFailoverFabricTargets.cmake
  NAMESPACE SwitchFailoverFabric::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SwitchFailoverFabric)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/SwitchFailoverFabricConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/SwitchFailoverFabricConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SwitchFailoverFabric)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/SwitchFailoverFabricConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/SwitchFailoverFabricConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/SwitchFailoverFabricConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SwitchFailoverFabric)

install(FILES LICENSE README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/SwitchFailoverFabric
  OPTIONAL)

message(STATUS "Switch Failover Fabric ${PROJECT_VERSION}")
message(STATUS "  build type        : ${CMAKE_BUILD_TYPE}")
message(STATUS "  tests             : ${SFF_BUILD_TESTS}")
message(STATUS "  tools             : ${SFF_BUILD_TOOLS}")
message(STATUS "  examples          : ${SFF_BUILD_EXAMPLES}")
message(STATUS "  warnings as errors: ${SFF_WARNINGS_AS_ERRORS}")
message(STATUS "  ASan              : ${SFF_ENABLE_ASAN}")
