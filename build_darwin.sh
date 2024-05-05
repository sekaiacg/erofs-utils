OUT="./out"
BUILD_DIR="./build/cmake"
EROFS_VERSION="v$(. scripts/get-version-number)"

cmake_build()
{
	local TARGET=$1
	local METHOD=$2
	local ABI=$3

	if [[ $METHOD == "Ninja" ]]; then
		local BUILD_METHOD="-G Ninja"
		echo ${CMAKE_CMD}
		local MAKE_CMD="time -p ninja -C $OUT"
	elif [[ $METHOD == "make" ]]; then
		local MAKE_CMD="time -p make -C $OUT -j$(sysctl -n hw.logicalcpu)"
	fi;

	local PROCESSOR=""
	[ ${ABI} == "x86_64" ] && PROCESSOR="x86_64"
	[ ${ABI} == "aarch64" ] && PROCESSOR="arm64"

	if [[ $TARGET == "Darwin" ]]; then
		cmake -S ${BUILD_DIR} -B ${OUT} ${BUILD_METHOD} \
			-DCMAKE_SYSTEM_NAME="Darwin" \
			-DCMAKE_SYSTEM_PROCESSOR="${PROCESSOR}" \
			-DCMAKE_BUILD_TYPE="Release" \
			-DCMAKE_C_COMPILER_TARGET="${ABI}-apple-darwin" \
			-DCMAKE_CXX_COMPILER_TARGET="${ABI}-apple-darwin" \
			-DCMAKE_OSX_DEPLOYMENT_TARGET="10.15" \
			-DCMAKE_C_COMPILER_LAUNCHER="ccache" \
			-DCMAKE_CXX_COMPILER_LAUNCHER="ccache" \
			-DCMAKE_C_COMPILER="clang" \
			-DCMAKE_CXX_COMPILER="clang++" \
			-DCMAKE_C_FLAGS="" \
			-DCMAKE_CXX_FLAGS="" \
			-DENABLE_FULL_LTO="ON" \
			-DMAX_BLOCK_SIZE="4096"
	fi

	${MAKE_CMD}
}

build()
{
	local TARGET=$1
	local ABI=$2
	local PLATFORM=$3

	rm -r $OUT > /dev/null 2>&1

	local NINJA=`which ninja`
	if [[ -f $NINJA ]]; then
		local METHOD="Ninja"
	else
		local METHOD="make"
	fi

	cmake_build "${TARGET}" "${METHOD}" "${ABI}" "${PLATFORM}"

	local BUILD="$OUT/erofs-tools"
	local DUMP_BIN="$BUILD/dump.erofs"
	local FSCK_BIN="$BUILD/fsck.erofs"
	local MKFS_BIN="$BUILD/mkfs.erofs"
	local EXTRACT_BIN="$BUILD/extract.erofs"
	local TARGE_DIR_NAME="erofs-utils-${EROFS_VERSION}-${TARGET}_${ABI}-$(TZ=UTC-8 date +%y%m%d%H%M)"
	local TARGET_DIR_PATH="./target/${TARGET}_${ABI}/${TARGE_DIR_NAME}"

	if [ -f "$DUMP_BIN" -a -f "$FSCK_BIN" -a -f "$MKFS_BIN" -a -f "$EXTRACT_BIN" ]; then
		echo "复制文件中..."
		[[ ! -d "$TARGET_DIR_PATH" ]] && mkdir -p ${TARGET_DIR_PATH}
		cp -af $BUILD/*.erofs ${TARGET_DIR_PATH}
		touch -c -d "2009-01-01 00:00:00" ${TARGET_DIR_PATH}/*
		echo "编译成功: ${TARGE_DIR_NAME}"
	else
		echo "error"
		exit 1
	fi
}

build "Darwin" "x86_64"
build "Darwin" "aarch64"

exit 0
