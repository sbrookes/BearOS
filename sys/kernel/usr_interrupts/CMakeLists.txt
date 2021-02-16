set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -Wl,-T -Wl,${BEAR_SOURCE_DIR}/sys/kernel/usr_interrupts/usr_intr.ld,-S,-N")
#set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -Wl,--oformat=binary,-Ttext=0x7c00,-N,-S,-estart")

set(USR_INTR_FILES
  usr_intr.c
  usr_intr.S
)

# build the kernel executable from the sources
add_executable(usr_intr ${USR_INTR_FILES})

