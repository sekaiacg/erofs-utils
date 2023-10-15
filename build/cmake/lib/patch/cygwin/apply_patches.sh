#!/usr/bin/bash
set -e

CURRENT_DIR="$(readlink -f $(dirname $0))"
TARGET_SRC_DIR="$(readlink -f $1)"

LIBSELINUX="$TARGET_SRC_DIR/selinux"
LIBBASE="$TARGET_SRC_DIR/libbase"
LIBLOG="$TARGET_SRC_DIR/logging"
LIBCUTILS="$TARGET_SRC_DIR/core"

# apply patch
gitapply() {
    patchdir="$1"
    shift 1
    cd $patchdir
    for i in $@; do
        git reset --hard > /dev/null
        printf "\x1b[93m- Apply Patch [%s] -> [%s] ... " "$(basename $i)" "$(basename $patchdir)"
        git apply "$i" >/dev/null 2>&1 && printf "\x1b[92mDone\x1b[0m\n" || printf "\x1b[91mFailed\x1b[0m\n"
    done
    cd $CURRENT_DIR
}

# Patch
gitapply $LIBBASE \
    "$CURRENT_DIR/0001-Cygwin-libbase-Add-cygwin-flags.patch"

gitapply $LIBSELINUX \
    "$CURRENT_DIR/0001-Cygwin-libselinux-Replace-__selinux_once-to-__pthrea.patch"

gitapply $LIBLOG \
    "$CURRENT_DIR/0001-Cygwin-liblog-Add-cygwin-flags.patch"

# Exit anyway
true