if(SECURE)
    message("Generating secure HEVD build configuration")
else()
    message("Generating vulnerable HEVD build configuration")
endif()


lkm_add_driver(
    NAME
        HEVD
    HackSysExtremeVulnerableDriver.c
    BufferOverflowStack.c
    IntegerOverflow.c
)
