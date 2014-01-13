include_directories(
  ${CMAKE_SOURCE_DIR}/main
  ${SIGAR_INCLUDE_DIRS}
  ${CONNEXTDDS_INCLUDE_DIRS}
  )

add_definitions(${CONNEXTDDS_DEFINITIONS})

file(GLOB_RECURSE disk_sources
  ${CMAKE_SOURCE_DIR}/plugins/disk/*.hpp
  ${CMAKE_SOURCE_DIR}/plugins/disk/*.cpp
  )

add_library(disk SHARED ${disk_sources})
target_link_libraries(disk ${SIGAR_LIBRARIES} ${CONNEXTDDS_LIBRARIES})
foreach(output_config ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${output_config} output_config)
  set_target_properties(disk PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_${output_config} 
    ${CMAKE_SOURCE_DIR}/plugins/disk
    LIBRARY_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/disk
    ARCHIVE_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/disk
    )
endforeach()
