
file(GLOB SRCS "${PROJECT_SOURCE_DIR}/fuse/*.c") 
add_executable(erofs.fuse ${SRCS})
target_link_libraries(erofs.fuse 
    libbase
    libutils
    liblog
    )

include_directories(
    ${PROJECT_SOURCE_DIR}/lib
    ${PROJECT_SOURCE_DIR}/include
    )
