include_directories(
  ${SIGAR_INCLUDE_DIRS}
  ${CONNEXTDDS_INCLUDE_DIRS}
  )

add_definitions(${CONNEXTDDS_DEFINITIONS})

file(GLOB_RECURSE cavecanem_sources
  ${CMAKE_SOURCE_DIR}/main/*.hpp
  ${CMAKE_SOURCE_DIR}/main/*.cpp
  )

add_executable(cavecanem ${cavecanem_sources})
target_link_libraries(cavecanem ${SIGAR_LIBRARIES} ${CONNEXTDDS_LIBRARIES})
set_target_properties(cavecanem PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
foreach (output_config ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${output_config} output_config)
  set_target_properties(cavecanem PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_${output_config} 
    ${CMAKE_SOURCE_DIR}
    LIBRARY_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}
    ARCHIVE_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}
    )
endforeach()
