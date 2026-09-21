# Switch Failover Fabric - verification suites.
#
# Permanent rule: no test in this directory sets a timeout of any kind, and nothing here wraps a
# test in a watchdog. A hang is a defect in the code under test and must be diagnosed rather than
# masked, so CTest's TIMEOUT property is deliberately never set.

function(sff_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE sff)
  target_link_libraries(${name} PRIVATE $<BUILD_INTERFACE:sff_build_options>)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

sff_add_test(test_core test_core.cpp)
sff_add_test(test_integrity test_integrity.cpp)
sff_add_test(test_frame_codec test_frame_codec.cpp)
sff_add_test(test_persistence test_persistence.cpp)
sff_add_test(test_topology test_topology.cpp)
sff_add_test(test_evidence test_evidence.cpp)
sff_add_test(test_authority test_authority.cpp)
sff_add_test(test_planner test_planner.cpp)
sff_add_test(test_validator test_validator.cpp)
sff_add_test(test_reference_solver test_reference_solver.cpp)
sff_add_test(test_property test_property.cpp)
sff_add_test(test_integration test_integration.cpp)
sff_add_test(test_adversarial test_adversarial.cpp)
sff_add_test(test_concurrency test_concurrency.cpp)
sff_add_test(test_lifecycle test_lifecycle.cpp)
sff_add_test(test_scale test_scale.cpp)
sff_add_test(test_restart test_restart.cpp)
sff_add_test(test_consumer_contract test_consumer_contract.cpp)

# Real multiprocess proof: independent operating-system processes over real loopback sockets.
add_executable(sff_mp_worker mp_worker.cpp)
target_link_libraries(sff_mp_worker PRIVATE sff)
target_link_libraries(sff_mp_worker PRIVATE $<BUILD_INTERFACE:sff_build_options>)
target_include_directories(sff_mp_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_multiprocess test_multiprocess.cpp)
target_link_libraries(test_multiprocess PRIVATE sff)
target_link_libraries(test_multiprocess PRIVATE $<BUILD_INTERFACE:sff_build_options>)
target_include_directories(test_multiprocess PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_multiprocess
         COMMAND test_multiprocess
                 $<TARGET_FILE:sff_mp_worker>
                 ${CMAKE_CURRENT_BINARY_DIR}/mp-scratch)
# ---------------------------------------------------------------------------------------------
# Header self-containment: one translation unit per public header, each including ONLY that
# header. A header that depends on another header being included first fails to compile here.
# ---------------------------------------------------------------------------------------------
file(GLOB_RECURSE SFF_PUBLIC_HEADERS RELATIVE ${CMAKE_SOURCE_DIR}/include
     ${CMAKE_SOURCE_DIR}/include/sff/*.hpp)

set(SFF_HEADER_TUS "")
foreach(header ${SFF_PUBLIC_HEADERS})
  string(REPLACE "/" "_" stem "${header}")
  string(REPLACE "." "_" stem "${stem}")
  string(REPLACE "-" "_" stem "${stem}")
  set(tu "${CMAKE_CURRENT_BINARY_DIR}/headers/${stem}.cpp")
  file(WRITE "${tu}" "#include \"${header}\"\nint sff_header_anchor_${stem}(void) { return 0; }\n")
  list(APPEND SFF_HEADER_TUS "${tu}")
endforeach()

add_library(sff_header_self_containment OBJECT ${SFF_HEADER_TUS})
target_link_libraries(sff_header_self_containment PRIVATE $<BUILD_INTERFACE:sff_build_options>)
target_include_directories(sff_header_self_containment PRIVATE ${CMAKE_SOURCE_DIR}/include)
message(STATUS "header self-containment units: ${CMAKE_MATCH_0}")