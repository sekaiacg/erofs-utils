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

	local FLAGS="-O3 -fdata-sections -ffunction-sections -funwind-tables -fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -fvisibility=hidden -fvisibility-inlines-hidden -fno-exceptions"

	if [[ $TARGET == "Android" ]]; then
		local ANDROID_PLATFORM=$4
		cmake -S ${BUILD_DIR} -B $OUT ${BUILD_METHOD} \
			-DNDK_CCACHE="ccache" \
			-DCMAKE_BUILD_TYPE="Release" \
			-DANDROID_PLATFORM="$ANDROID_PLATFORM" \
			-DANDROID_ABI="$ABI" \
			-DANDROID_STL="c++_static" \
			-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
			-DANDROID_USE_LEGACY_TOOLCHAIN_FILE="OFF" \
			-DCMAKE_C_FLAGS="-DANDROID ${FLAGS} -mllvm -polly" \
			-DCMAKE_CXX_FLAGS="-DANDROID ${FLAGS} -mllvm -polly -fno-rtti" \
			-DEROFS_LINKER_FLAGS="-static -s"
	elif [[ $TARGET == "Linux" ]]; then
		if [[ $ABI == "x86_64" ]]; then
			LINUX_BIT=64
		elif [[ $ABI == "x86" ]]; then
			LINUX_BIT=32
		fi
		##指定第三方clang 路径：CLANG_PATH=""
		local LFLAGS="-fuse-ld=lld -Wl,--build-id=sha1 -Wl,--fatal-warnings -Wl,--gc-sections -Qunused-arguments -Wl,--no-undefined -Wl,--gc-sections -static -s"
		cmake -S ${BUILD_DIR} -B $OUT ${BUILD_METHOD} \
			-DCMAKE_C_COMPILER_LAUNCHER="ccache" \
			-DCMAKE_CXX_COMPILER_LAUNCHER="ccache" \
			-DCMAKE_C_COMPILER="clang" \
			-DCMAKE_CXX_COMPILER="clang++" \
			-DCMAKE_C_FLAGS="-m${LINUX_BIT} ${FLAGS}" \
			-DCMAKE_CXX_FLAGS="-m${LINUX_BIT} ${FLAGS} -fno-rtti" \
			-DCMAKE_EXE_LINKER_FLAGS="${LFLAGS}"
	fi

	${MAKE_CMD}
}

build()
{
	local TARGET=$1
	local ABI=$2
	local ANDROID_PLATFORM=$3

	rm -r $OUT > /dev/null 2>&1

	local NINJA=`which ninja`
	if [[ -f $NINJA ]]; then
		local METHOD="Ninja"
	else
		local METHOD="make"
	fi

	cmake_build "${TARGET}" "${METHOD}" "${ABI}" "${ANDROID_PLATFORM}"

	local BUILD="$OUT/erofs-tools"
	local DUMP_BIN="$BUILD/dump.erofs"
	local FSCK_BIN="$BUILD/fsck.erofs"
	local FUSE_BIN="$BUILD/fuse.erofs"
	local MKFS_BIN="$BUILD/mkfs.erofs"
	local TARGET_DIR="./target/${TARGET}_${ABI}/erofs-utils-${EROFS_VERSION}-${TARGET}_${ABI}-$(TZ=UTC-8 date +%y%m%d%H%M)"

	if [ -f "$DUMP_BIN" -a -f "$FSCK_BIN" -a -f "$FUSE_BIN" -a -f "$MKFS_BIN" ]; then
		echo "打包中..."
		[[ ! -d "$TARGET_DIR" ]] && mkdir -p ${TARGET_DIR}
		cp -af $BUILD/*.erofs ${TARGET_DIR}
		echo "打包完成！"
	else
		echo "error"
		exit -1
	fi
}

build "Android" "arm64-v8a" "android-31"
build "Android" "armeabi-v7a" "android-31"
build "Android" "x86_64" "android-31"
build "Android" "x86" "android-31"
build "Linux" "x86_64"
build "Linux" "x86"

exit 0
