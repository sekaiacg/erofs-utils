set(TARGET cxx)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libcxx")
set(LIBCXX_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/libcxx")
set(LIBCXX_VERSION_STRING "19.0.0")
set(LIBCXX_VERSION_MARJO "19")

file(GLOB SRCS ${TARGET_SRC_DIR}/src/*.cpp)
file(GLOB FILESYSTEM_SRCS ${TARGET_SRC_DIR}/src/filesystem/*.cpp)
file(GLOB RYU_SRCS ${TARGET_SRC_DIR}/src/ryu/*.cpp)

set(LIBCXX_SOURCES
    ${SRCS}
    ${FILESYSTEM_SRCS}
    ${RYU_SRCS}
)
#list(TRANSFORM LIBCXX_SOURCES PREPEND ${TARGET_SRC_DIR}/src/)

set(LIBCXX_EXPORT_FLAGS
)

set(LIBCXX_CXXFLAGS
    #    -fvisibility-global-new-delete-hidden
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -DLIBCXX_BUILDING_LIBCXXABI
    -D_LIBCPP_NO_EXCEPTIONS
    -D_LIBCPP_NO_RTTI
    -D_LIBCPP_BUILDING_LIBRARY
    -D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS
    -D_LIBCXXABI_NO_EXCEPTIONS
)

check_compile_flag_supported(-fvisibility-global-new-delete=force-hidden IF_SUPPORT)
if (IF_SUPPORT)
    list(APPEND LIBCXX_CXXFLAGS -fvisibility-global-new-delete=force-hidden)
else ()
    list(APPEND LIBCXX_CXXFLAGS -fvisibility-global-new-delete-hidden)
endif ()

set(LIBCXX_EXPORT_INCLUDES ${TARGET_SRC_DIR}/include)
set(LIBCXX_INCLUDES ${TARGET_SRC_DIR}/src)

set(LIBCXXABI_SOURCES
    abort_message.cpp
    cxa_aux_runtime.cpp
    cxa_default_handlers.cpp
    cxa_exception_storage.cpp
    cxa_guard.cpp
    cxa_handlers.cpp
    cxa_noexception.cpp
    cxa_thread_atexit.cpp
    cxa_vector.cpp
    cxa_virtual.cpp
    stdlib_exception.cpp
    stdlib_new_delete.cpp
    stdlib_stdexcept.cpp
    stdlib_typeinfo.cpp
)
list(TRANSFORM LIBCXXABI_SOURCES PREPEND ${TARGET_SRC_DIR}/src/abi/)
set(LIBCXXABI_CFLAGS -D__STDC_FORMAT_MACROS)
set(LIBCXXABI_CXXFLAGS
    -Wno-macro-redefined
    -Wno-unknown-attributes
    -DHAS_THREAD_LOCAL
)
set(LIBCXXABI_INCLUDES ${TARGET_SRC_DIR}/include/abi)

add_library(${TARGET} STATIC ${LIBCXX_SOURCES} ${LIBCXXABI_SOURCES})

set_target_properties(${TARGET} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${LIBCXX_BINARY_DIR}
)

set_target_properties(${TARGET}
    PROPERTIES
    OUTPUT_NAME ${TARGET}_static
    VERSION ${LIBCXX_VERSION_STRING}
    SOVERSION ${LIBCXX_VERSION_MARJO}
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(${TARGET} PRIVATE ${LIBCXX_INCLUDES} ${LIBCXXABI_INCLUDES})
target_include_directories(${TARGET}
    PUBLIC $<BUILD_INTERFACE:${LIBCXX_EXPORT_INCLUDES}>
    INTERFACE $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_options(${TARGET} PUBLIC "$<$<COMPILE_LANGUAGE:CXX>:${LIBCXX_EXPORT_FLAGS}>")
set(LIBCXX_PRIVATE_FLAGS ${LIBCXX_CXXFLAGS} ${LIBCXXABI_CXXFLAGS} -ffunction-sections -fdata-sections)
target_compile_options(${TARGET} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:${LIBCXX_PRIVATE_FLAGS}>")
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBCXX_EXPORT_INCLUDES})

include(CMakePackageConfigHelpers)

install(TARGETS ${TARGET}
    EXPORT libcxxTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/libcxx"
)

set(LIBCXX_PKG_INSTALLDIR "${CMAKE_INSTALL_LIBDIR}/cmake/libcxx-${LIBCXX_VERSION_MARJO}")

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/libcxxConfig.cmake.in"
    "${LIBCXX_BINARY_DIR}/libcxxConfig.cmake"
    INSTALL_DESTINATION ${LIBCXX_PKG_INSTALLDIR}
)

write_basic_package_version_file(
    "${LIBCXX_BINARY_DIR}/libcxxConfigVersion.cmake"
    VERSION ${LIBCXX_VERSION_STRING}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${LIBCXX_BINARY_DIR}/libcxxConfig.cmake"
    "${LIBCXX_BINARY_DIR}/libcxxConfigVersion.cmake"
    DESTINATION ${LIBCXX_PKG_INSTALLDIR}
)

export(EXPORT libcxxTargets
    FILE libcxx/libcxxTargets.cmake
    NAMESPACE CXX::
)

install(EXPORT libcxxTargets
    FILE libcxxTargets.cmake
    NAMESPACE CXX::
    DESTINATION ${LIBCXX_PKG_INSTALLDIR}
)

link_libraries(${TARGET})
