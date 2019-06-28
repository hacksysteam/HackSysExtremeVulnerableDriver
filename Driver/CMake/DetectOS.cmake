#
# This script is used to detect the OS and architecture of the host system
#

# Detect host architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(HOST_ARCH_X86 TRUE BOOL)
    set(HOST_PLATFORM "x86")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(HOST_ARCH_X64 TRUE BOOL)
    set(HOST_PLATFORM "x64")
endif()


# Detect host operating system
string(REGEX MATCH "Linux" HOST_OS_LINUX ${CMAKE_SYSTEM_NAME})

if(WIN32)
    set(HOST_OS_WINDOWS TRUE BOOL)
endif()
