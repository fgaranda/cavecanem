include_directories(
  ${CMAKE_SOURCE_DIR}/main
  ${SIGAR_INCLUDE_DIRS}
  ${CONNEXTDDS_INCLUDE_DIRS}
  )

add_definitions(${CONNEXTDDS_DEFINITIONS})

file(GLOB_RECURSE cpu_sources
  ${CMAKE_SOURCE_DIR}/plugins/cpu/*.hpp
  ${CMAKE_SOURCE_DIR}/plugins/cpu/*.cpp
  )

add_library(cpu SHARED ${cpu_sources})
target_link_libraries(cpu ${SIGAR_LIBRARIES} ${CONNEXTDDS_LIBRARIES})
foreach(output_config ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${output_config} output_config)
  set_target_properties(cpu PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_${output_config} 
    ${CMAKE_SOURCE_DIR}/plugins/cpu
    LIBRARY_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/cpu
    ARCHIVE_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/cpu
    )
endforeach()