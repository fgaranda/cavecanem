include_directories(
  ${CMAKE_SOURCE_DIR}/main
  ${SIGAR_INCLUDE_DIRS}
  ${CONNEXTDDS_INCLUDE_DIRS}
  )

add_definitions(${CONNEXTDDS_DEFINITIONS})

file(GLOB_RECURSE proc_sources
  ${CMAKE_SOURCE_DIR}/plugins/proc/*.hpp
  ${CMAKE_SOURCE_DIR}/plugins/proc/*.cpp
  )

add_library(proc SHARED ${proc_sources})
target_link_libraries(proc ${SIGAR_LIBRARIES} ${CONNEXTDDS_LIBRARIES})
foreach(output_config ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${output_config} output_config)
  set_target_properties(proc PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_${output_config} 
    ${CMAKE_SOURCE_DIR}/plugins/proc
    LIBRARY_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/proc
    ARCHIVE_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/proc
    )
endforeach()
