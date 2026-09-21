# Switch Failover Fabric - independent downstream consumer.
#
# This project lives entirely outside the source tree's build: it only ever sees the INSTALLED
# package through find_package(... CONFIG REQUIRED). It is the proof that the exported targets,
# headers and version files are complete and usable.
cmake_minimum_required(VERSION 3.20)

project(sff_consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SwitchFailoverFabric 1.0 CONFIG REQUIRED)

add_executable(sff_consumer main.cpp)
target_link_libraries(sff_consumer PRIVATE SwitchFailoverFabric::sff)

# The consumer must not need any include directory beyond what the package exports.
get_target_property(sff_consumer_includes sff_consumer INCLUDE_DIRECTORIES)
if(sff_consumer_includes)
  message(FATAL_ERROR "consumer unexpectedly needed extra include directories: ${sff_consumer_includes}")
endif()

message(STATUS "consumer linked against SwitchFailoverFabric ${SwitchFailoverFabric_VERSION}")
