# Switch Failover Fabric - command line tools.
add_executable(sffctl sffctl.cpp)
target_link_libraries(sffctl PRIVATE sff)
target_link_libraries(sffctl PRIVATE $<BUILD_INTERFACE:sff_build_options>)
set_target_properties(sffctl PROPERTIES OUTPUT_NAME "sffctl")
install(TARGETS sffctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
