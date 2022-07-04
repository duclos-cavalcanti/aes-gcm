add_custom_target("debug"
    COMMENT "Debugging with GDB"
    DEPENDS ${PROJECT_TEST_NAME}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMAND gdb -tui bin/${PROJECT_TEST_NAME}
)
