
add_custom_target("run"
    COMMENT "Running Program"
    DEPENDS ${PROJECT_BIN}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMAND bin/${PROJECT_BIN}
)

