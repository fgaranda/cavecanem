include_directories(
  ${CMAKE_SOURCE_DIR}/main
  ${SIGAR_INCLUDE_DIRS}
  ${CONNEXTDDS_INCLUDE_DIRS}
  )

add_definitions(${CONNEXTDDS_DEFINITIONS})

file(GLOB_RECURSE memory_sources
  ${CMAKE_SOURCE_DIR}/plugins/memory/*.hpp
  ${CMAKE_SOURCE_DIR}/plugins/memory/*.cpp
  )

add_library(memory SHARED ${memory_sources})
target_link_libraries(memory ${SIGAR_LIBRARIES} ${CONNEXTDDS_LIBRARIES})
foreach(output_config ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${output_config} output_config)
  set_target_properties(memory PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_${output_config} 
    ${CMAKE_SOURCE_DIR}/plugins/memory
    LIBRARY_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/memory
    ARCHIVE_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/memory
    )
endforeach()
