# - Try to find the secp256k1 library
#
# Once done this will define:
#  secp256k1_FOUND        - System has secp256k1
#  secp256k1_INCLUDE_DIRS - The secp256k1 include directories
#  secp256k1_LIBRARIES    - The libraries needed to use secp256k1
#
# It also defines an imported target:
#  secp256k1::secp256k1

find_path(
        secp256k1_INCLUDE_DIR secp256k1.h
        HINTS ${secp256k1_DIR}
        PATH_SUFFIXES include
)

find_library(
        secp256k1_LIBRARY NAMES secp256k1
        HINTS ${secp256k1_DIR}
        PATH_SUFFIXES lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
        secp256k1
        DEFAULT_MSG
        secp256k1_LIBRARY
        secp256k1_INCLUDE_DIR
)

mark_as_advanced(secp256k1_INCLUDE_DIR secp256k1_LIBRARY)

if(secp256k1_FOUND AND NOT TARGET secp256k1::secp256k1)
    add_library(secp256k1::secp256k1 UNKNOWN IMPORTED)
    set_target_properties(
            secp256k1::secp256k1
            PROPERTIES
            IMPORTED_LOCATION "${secp256k1_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${secp256k1_INCLUDE_DIR}"
    )
endif()