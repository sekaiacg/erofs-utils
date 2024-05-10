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
		local MAKE_CMD="time -p make -C $OUT -j$(nproc)"
	fi;

	if [[ $TARGET == "Android" ]]; then
		local ANDROID_PLATFORM=$4
		cmake -S ${BUILD_DIR} -B $OUT ${BUILD_METHOD} \
			-DNDK_CCACHE="ccache" \
			-DCMAKE_BUILD_TYPE="Release" \
			-DANDROID_PLATFORM="$ANDROID_PLATFORM" \
			-DANDROID_ABI="$ABI" \
			-DANDROID_STL="none" \
			-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
			-DANDROID_USE_LEGACY_TOOLCHAIN_FILE="OFF" \
			-DCMAKE_C_FLAGS="" \
			-DCMAKE_CXX_FLAGS="" \
			-DENABLE_FULL_LTO="ON" \
			-DMAX_BLOCK_SIZE="4096"
	elif [[ $TARGET == "Linux" ]]; then
		local LINUX_PLATFORM=$4
		local WSL="OFF"
		[ "${LINUX_PLATFORM}" == "WSL" ] && WSL="ON"
		if [[ ${ABI} == "x86_64" ]]; then
			cmake -S ${BUILD_DIR} -B ${OUT} ${BUILD_METHOD} \
				-DCMAKE_SYSTEM_NAME="Linux" \
				-DCMAKE_SYSTEM_PROCESSOR="x86_64" \
				-DCMAKE_BUILD_TYPE="Release" \
				-DRUN_ON_WSL="${WSL}" \
				-DCMAKE_C_COMPILER_LAUNCHER="ccache" \
				-DCMAKE_CXX_COMPILER_LAUNCHER="ccache" \
				-DCMAKE_C_COMPILER="${CUSTOM_CLANG_PATH}/bin/clang" \
				-DCMAKE_CXX_COMPILER="${CUSTOM_CLANG_PATH}/bin/clang++" \
				-DCMAKE_C_FLAGS="" \
				-DCMAKE_CXX_FLAGS="" \
				-DENABLE_FULL_LTO="ON" \
				-DMAX_BLOCK_SIZE="4096"
		elif [[ ${ABI} == "loongarch64" ]]; then
			cmake -S ${BUILD_DIR} -B ${OUT} ${BUILD_METHOD} \
				-DCMAKE_SYSTEM_NAME="Linux" \
				-DCMAKE_SYSTEM_PROCESSOR="loongarch64" \
				-DCMAKE_BUILD_TYPE="Release" \
				-DRUN_ON_WSL="${WSL}" \
				-DCMAKE_C_COMPILER_LAUNCHER="ccache" \
				-DCMAKE_CXX_COMPILER_LAUNCHER="ccache" \
				-DCMAKE_C_COMPILER="${CUSTOM_CLANG_PATH}/bin/clang" \
				-DCMAKE_CXX_COMPILER="${CUSTOM_CLANG_PATH}/bin/clang++" \
				-DCMAKE_SYSROOT="${LOONGARCH64_GCC_PATH}/target" \
				-DCMAKE_C_COMPILER_TARGET="loongarch64-linux-gnu" \
				-DCMAKE_CXX_COMPILER_TARGET="loongarch64-linux-gnu" \
				-DCMAKE_C_FLAGS="--gcc-toolchain=${LOONGARCH64_GCC_PATH}" \
				-DCMAKE_CXX_FLAGS="--gcc-toolchain=${LOONGARCH64_GCC_PATH}" \
				-DENABLE_FULL_LTO="OFF" \
				-DMAX_BLOCK_SIZE="4096"
		fi
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

	[ "${PLATFORM}" == "WSL" ] && TARGET="WSL"

	local BUILD="$OUT/erofs-tools"
	local DUMP_BIN="$BUILD/dump.erofs"
	local FSCK_BIN="$BUILD/fsck.erofs"
	local FUSE_BIN="$BUILD/fuse.erofs"
	local MKFS_BIN="$BUILD/mkfs.erofs"
	local EXTRACT_BIN="$BUILD/extract.erofs"
	local TARGE_DIR_NAME="erofs-utils-${EROFS_VERSION}-${TARGET}_${ABI}-$(TZ=UTC-8 date +%y%m%d%H%M)"
	local TARGET_DIR_PATH="./target/${TARGET}_${ABI}/${TARGE_DIR_NAME}"

	if [ -f "$DUMP_BIN" -a -f "$FSCK_BIN" -a -f "$FUSE_BIN" -a -f "$MKFS_BIN" -a -f "$EXTRACT_BIN" ]; then
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

build "Android" "arm64-v8a" "android-31"
build "Android" "armeabi-v7a" "android-31"
build "Android" "x86_64" "android-31"
build "Android" "x86" "android-31"
build "Linux" "x86_64"
build "Linux" "x86_64" "WSL"
build "Linux" "loongarch64"

exit 0
