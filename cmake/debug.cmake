add_custom_target("debug"
    COMMENT "Debugging with GDB"
    DEPENDS ${PROJECT_BIN}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMAND gdb -tui bin/${PROJECT_BIN}
)
