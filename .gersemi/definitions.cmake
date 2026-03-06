# Custom CMake command definitions for gersemi formatting.
# These stubs teach gersemi the signatures of project-specific commands
# so it can format their invocations correctly.

function(add_mpt_test TEST_NAME TEST_SOURCE)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs DEPENDENCIES)

    cmake_parse_arguments(
        THIS_FUNCTION_PREFIX
        "${options}"
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN}
    )
endfunction()
