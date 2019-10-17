#
# Intermediate CMakeLists to add OS dependent directories
#

if(HOST_OS_WINDOWS)
    add_subdirectory("Windows")
elseif(HOST_OS_LINUX)
    add_subdirectory("Linux")
endif()
