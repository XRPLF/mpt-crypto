# --- Installation ---
include(GNUInstallDirs)

# Install the library
install(TARGETS mpt-crypto
        EXPORT mpt-crypto-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install the header files
install(FILES include/secp256k1_mpt.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export the targets to a script
install(EXPORT mpt-crypto-targets FILE mpt-crypto-targets.cmake NAMESPACE mpt-crypto::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mpt-crypto)

# Create a ConfigVersion file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/mpt-crypto-config-version.cmake VERSION 1.0.0
                                 COMPATIBILITY AnyNewerVersion)

# Create a Config file
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/mpt-crypto-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/mpt-crypto-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mpt-crypto)

# Install the config and version files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mpt-crypto-config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/mpt-crypto-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mpt-crypto)
