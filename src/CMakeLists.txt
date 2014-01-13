cmake_minimum_required(VERSION 2.8.7)
# Cave Canem 0.2
project(cavecanem)
set(cavecanem_VERSION_MAJOR 0)
set(cavecanem_VERSION_MINOR 2)

# Add cmake scripts directory to the modules path
# -----------------------------------------------
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/cmake )

# Requirements
find_package(HypericSigar REQUIRED)
find_package(ConnextDDS REQUIRED)

# Define Source Path
add_definitions(-DCAVECANEM_DIR="${CMAKE_SOURCE_DIR}/..")

# Plugins
add_subdirectory(plugins/cpu)
add_subdirectory(plugins/disk)
add_subdirectory(plugins/host_info)
add_subdirectory(plugins/memory)
add_subdirectory(plugins/net_load)
add_subdirectory(plugins/proc)
add_subdirectory(plugins/proc_stat)

# Main App
add_subdirectory(main)
