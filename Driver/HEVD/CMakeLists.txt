
if(SECURE)
    add_definitions(-DSECURE)
    message("Generating secure HEVD build configuration")
else()
    message("Generating vulnerable HEVD build configuration")
endif()


wdk_add_driver(HEVD
    WDM
        1.15
    PFX_FILE
        HEVD.pfx
    PFX_PASSWORD
        Passw0rd!
    HackSysExtremeVulnerableDriver.c
    ArbitraryReadWriteHelperNonPagedPoolNx.c
    ArbitraryWrite.c
    BufferOverflowNonPagedPool.c
    BufferOverflowNonPagedPoolNx.c
    BufferOverflowPagedPoolSession.c
    BufferOverflowStack.c
    BufferOverflowStackGS.c
    DoubleFetch.c
    InsecureKernelResourceAccess.c
    IntegerOverflow.c
    MemoryDisclosureNonPagedPool.c
    MemoryDisclosureNonPagedPoolNx.c
    NullPointerDereference.c
    TypeConfusion.c
    UninitializedMemoryPagedPool.c
    UninitializedMemoryStack.c
    UseAfterFreeNonPagedPool.c
    UseAfterFreeNonPagedPoolNx.c
    WriteNULL.c
)
