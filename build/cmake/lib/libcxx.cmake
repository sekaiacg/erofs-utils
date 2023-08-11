set(TARGET cxx)

set(TARGET_SRC_DIR "${LIB_DIR}/libcxx")

set(LIBCXX_SOURCES
    algorithm.cpp
    any.cpp
    atomic.cpp
    barrier.cpp
    bind.cpp
    charconv.cpp
    chrono.cpp
    condition_variable.cpp
    condition_variable_destructor.cpp
    debug.cpp
    exception.cpp
    filesystem/directory_iterator.cpp
    filesystem/int128_builtins.cpp
    filesystem/operations.cpp
    functional.cpp
    future.cpp
    hash.cpp
    ios.cpp
    ios.instantiations.cpp
    iostream.cpp
    legacy_debug_handler.cpp
    legacy_pointer_safety.cpp
    locale.cpp
    memory.cpp
    memory_resource.cpp
    mutex.cpp
    mutex_destructor.cpp
    new.cpp
    optional.cpp
    random_shuffle.cpp
    random.cpp
    regex.cpp
    shared_mutex.cpp
    stdexcept.cpp
    string.cpp
    strstream.cpp
    system_error.cpp
    thread.cpp
    typeinfo.cpp
    utility.cpp
    valarray.cpp
    variant.cpp
    vector.cpp
    verbose_abort.cpp
)

list(TRANSFORM LIBCXX_SOURCES PREPEND ${TARGET_SRC_DIR}/src/)

set(LIBCXX_EXPORT_FLAGS)
set(LIBCXX_FLAGS
    -std=c++20
    -fvisibility-global-new-delete-hidden
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -DLIBCXX_BUILDING_LIBCXXABI
    -D_LIBCPP_NO_EXCEPTIONS
    -D_LIBCPP_NO_RTTI
    -D_LIBCPP_BUILDING_LIBRARY
    -D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS
    -D__STDC_FORMAT_MACROS
)
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
set(LIBCXXABI_FLAGS
    -D_LIBCXXABI_NO_EXCEPTIONS
    -Wno-macro-redefined
    -Wno-unknown-attributes
    -DHAS_THREAD_LOCAL
)
set(LIBCXXABI_INCLUDES ${TARGET_SRC_DIR}/include/abi)

add_library(${TARGET} STATIC ${LIBCXX_SOURCES} ${LIBCXXABI_SOURCES})
target_compile_options(${TARGET} PUBLIC ${LIBCXX_EXPORT_FLAGS})
target_compile_options(${TARGET} PRIVATE ${LIBCXX_FLAGS} ${LIBCXXABI_FLAGS} -ffunction-sections -fdata-sections)
target_include_directories(${TARGET} PUBLIC ${LIBCXX_EXPORT_INCLUDES})
target_include_directories(${TARGET} PRIVATE ${LIBCXX_INCLUDES} ${LIBCXXABI_INCLUDES})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBCXX_EXPORT_INCLUDES})
link_libraries(${TARGET})
