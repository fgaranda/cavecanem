# FindHypericSigar.cmake

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
  # Build for Linux
  if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32-bit Linux
    set(sigar_library_name sigar-x86-linux)
  else()
    # 64-bit Linux
    set(sigar_library_name sigar-amd64-linux)
  endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
  # Build for Windows
  set(sigar_library_name sigar-x86-winnt)
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  # Build for Mac
  set(sigar_library_name libsigar-universal64-macosx.a)
  set(SIGAR_LINK_FLAGS "-framework CoreServices -framework IOKit")  
endif()

find_path(SIGAR_INCLUDE_DIRS
  NAMES sigar.h
  PATHS ${CMAKE_SOURCE_DIR}/shared/hyperic_sigar-1.6.4/include
  )
find_library(SIGAR_LIBRARIES 
  NAMES ${sigar_library_name}
  PATHS ${CMAKE_SOURCE_DIR}/shared/hyperic_sigar-1.6.4/lib
  )
set(SIGAR_LIBRARIES
  ${SIGAR_LIBRARIES}
  ${SIGAR_LINK_FLAGS}
  )
