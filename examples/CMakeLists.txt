# Switch Failover Fabric - example programs.
# Each example is also compiled against the installed package by the downstream consumer check.

function(sff_add_example name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE sff)
  target_link_libraries(${name} PRIVATE $<BUILD_INTERFACE:sff_build_options>)
endfunction()

sff_add_example(example_failover example_failover.cpp)
sff_add_example(example_planning example_planning.cpp)
sff_add_example(example_restart example_restart.cpp)
