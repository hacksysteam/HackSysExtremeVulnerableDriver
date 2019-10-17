#
# Linux Kernel Module Builder
#

# set the kernel build directory
set(KERNEL_DIR "/lib/modules/${CMAKE_HOST_SYSTEM_VERSION}/build")

message(STATUS "KERNEL_VERSION: ${CMAKE_HOST_SYSTEM_VERSION}")
message(STATUS "KERNEL_DIR: ${KERNEL_DIR}")


function(lkm_add_driver)
    cmake_parse_arguments(LKM "" "NAME" "" ${ARGN})

    # validate the module name
    if(NOT LKM_NAME)
        message(FATAL_ERROR "You should give a name to the module")
        return()
	else()
		string(TOLOWER ${LKM_NAME} MODULE_NAME)
    endif()

    # set the Kbuild command and file path
    set(KBUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -C ${KERNEL_DIR} M=${CMAKE_BINARY_DIR} src=${CMAKE_SOURCE_DIR}/HEVD/${CMAKE_SYSTEM_NAME})
    
    set(KBUILD_FILE_PATH "${CMAKE_SOURCE_DIR}/HEVD/${CMAKE_SYSTEM_NAME}/Kbuild")

    # delete the obsolete Kbuild file if exists
    if(EXISTS ${KBUILD_FILE_PATH})
        message(STATUS "Deleting obsolete Kbuild: ${KBUILD_FILE_PATH}")
        file(REMOVE ${KBUILD_FILE_PATH})
    endif()

    # add the source object files to the Kbuild file
    foreach(MODULE_SOURCE_FILE ${LKM_UNPARSED_ARGUMENTS})
        get_filename_component(SOURCE_FILE ${MODULE_SOURCE_FILE} NAME_WE)
        file(APPEND ${KBUILD_FILE_PATH} "${MODULE_NAME}-m += ${SOURCE_FILE}.o\n")
    endforeach()

    file(APPEND ${KBUILD_FILE_PATH} "obj-m += ${MODULE_NAME}.o\n")

    # disable -Wframe-larger-than= warning in GCC
    file(APPEND ${KBUILD_FILE_PATH} "ccflags-y := -Wframe-larger-than=65535\n")

    # if we are building secure version, then set the flag
    if(SECURE)
        file(APPEND ${KBUILD_FILE_PATH} "ccflags-y += -DSECURE\n")
    endif()

    message(STATUS "Wrote new Kbuild: ${KBUILD_FILE_PATH}")

    # set the output module path
	set(MODULE_BIN_FILE "${CMAKE_BINARY_DIR}/${MODULE_NAME}.ko")
    
    add_custom_target(
        ${MODULE_NAME}
        ALL COMMAND ${KBUILD_COMMAND} modules
        COMMENT "Compiling Linux Kernel Module: ${MODULE_BIN_FILE}"
    )

    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${KBUILD_FILE_PATH} ${CMAKE_BINARY_DIR})
    
endfunction()
