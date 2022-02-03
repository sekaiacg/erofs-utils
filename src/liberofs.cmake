set(TARGET erofs)

file(GLOB SRCS "${PROJECT_SOURCE_DIR}/lib/*.c") 

add_library(${TARGET} STATIC
    ${SRCS}
    )

include_directories(
    ${PROJECT_SOURCE_DIR}/lib
    ${PROJECT_SOURCE_DIR}/include
    )
