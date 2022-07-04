add_custom_target(
        reset
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/build/
        COMMENT "Cleaning Build Files"
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/build/*
        COMMAND touch .gitkeep
)
