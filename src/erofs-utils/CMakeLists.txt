set(EROFS_UTILS_DIR "${PROJECT_SOURCE_DIR}/src/lib/erofs-utils")

set(COMMON_LINK_LIBS erofs_utils_static)

###############################------mkfs.erofs------###############################
set(TARGET_mkfs mkfs.erofs)
file(GLOB mkfs_srcs "${EROFS_UTILS_DIR}/mkfs/*.c")
add_executable(${TARGET_mkfs} ${mkfs_srcs})
target_link_libraries(${TARGET_mkfs} ${COMMON_LINK_LIBS})
####################################################################################

###############################------dump.erofs------###############################
set(TARGET_dump dump.erofs)
file(GLOB dump_srcs "${EROFS_UTILS_DIR}/dump/*.c")
add_executable(${TARGET_dump} ${dump_srcs})
target_link_libraries(${TARGET_dump} ${COMMON_LINK_LIBS})
####################################################################################

###############################------fsck.erofs------###############################
set(TARGET_fsck fsck.erofs)
file(GLOB fsck_srcs "${EROFS_UTILS_DIR}/fsck/*.c")
add_executable(${TARGET_fsck} ${fsck_srcs})
target_link_libraries(${TARGET_fsck} ${COMMON_LINK_LIBS})
####################################################################################
