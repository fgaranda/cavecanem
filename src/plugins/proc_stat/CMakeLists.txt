include_directories(
  ${CMAKE_SOURCE_DIR}/main
  ${SIGAR_INCLUDE_DIRS}
  ${CONNEXTDDS_INCLUDE_DIRS}
  )

add_definitions(${CONNEXTDDS_DEFINITIONS})

file(GLOB_RECURSE proc_stat_sources
  ${CMAKE_SOURCE_DIR}/plugins/proc_stat/*.hpp
  ${CMAKE_SOURCE_DIR}/plugins/proc_stat/*.cpp
  )

add_library(proc_stat SHARED ${proc_stat_sources})
target_link_libraries(proc_stat ${SIGAR_LIBRARIES} ${CONNEXTDDS_LIBRARIES})
foreach(output_config ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${output_config} output_config)
  set_target_properties(proc_stat PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_${output_config} 
    ${CMAKE_SOURCE_DIR}/plugins/proc_stat
    LIBRARY_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/proc_stat
    ARCHIVE_OUTPUT_DIRECTORY_${output_config}
    ${CMAKE_SOURCE_DIR}/plugins/proc_stat
    )
endforeach()
