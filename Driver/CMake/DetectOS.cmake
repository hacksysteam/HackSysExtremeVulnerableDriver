#
# This script is used to detect the OS and architecture of the host system
#

# Detect host architecture
if(CMAKE_C_PLATFORM_ID STREQUAL "Windows")
    if(CMAKE_C_COMPILER_ARCHITECTURE_ID STREQUAL "X86")
        set(HOST_ARCH_X86 TRUE BOOL)
        set(HOST_PLATFORM "x86")
    elseif(CMAKE_C_COMPILER_ARCHITECTURE_ID STREQUAL "x64")
        set(HOST_ARCH_X64 TRUE BOOL)
        set(HOST_PLATFORM "x64")
    elseif(CMAKE_C_COMPILER_ARCHITECTURE_ID STREQUAL "ARM64")
        set(HOST_ARCH_ARM64 TRUE BOOL)
        set(HOST_PLATFORM "arm64")
    endif()
elseif(CMAKE_C_PLATFORM_ID STREQUAL "Linux")
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(HOST_ARCH_X86 TRUE BOOL)
        set(HOST_PLATFORM "x86")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(HOST_ARCH_X64 TRUE BOOL)
        set(HOST_PLATFORM "x64")
    endif()
endif()

# Detect host operating system
string(REGEX MATCH "Linux" HOST_OS_LINUX ${CMAKE_SYSTEM_NAME})

if(WIN32)
    set(HOST_OS_WINDOWS TRUE BOOL)
endif()
