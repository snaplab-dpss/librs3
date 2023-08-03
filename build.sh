#!/bin/bash

set -eo pipefail

function link {
    if [ ! -L $1 ]; then
        ln -sf $2 $1
    fi
}

RS3_DIR=$(dirname $(realpath -s $0))
BUILD_DIR=`pwd`

BUILD_TYPES_DIR="$BUILD_DIR/builds"
DEBUG_BUILD="$BUILD_TYPES_DIR/debug"
RELEASE_BUILD="$BUILD_TYPES_DIR/release"

RS3_LIBS_DIR="$BUILD_DIR/libs"
RS3_INCLUDE_DIR="$BUILD_DIR/include"
RS3_EXAMPLES_DEBUG_DIR="$BUILD_DIR/examples-debug"
RS3_EXAMPLES_RELEASE_DIR="$BUILD_DIR/examples-release"
RS3_DOCS_DIR="$BUILD_DIR/docs"

if [ -z $Z3_DIR ]; then
    echo "This project is dependent on the Z3 project."
    echo "Please set the environmental variable \"Z3_DIR\" with the path to that project."    
    exit 1
fi

# Build debug

echo "[*] Building debug and examples"

mkdir -p $DEBUG_BUILD
cd $DEBUG_BUILD
CMAKE_PREFIX_PATH="$Z3_DIR/build" CMAKE_INCLUDE_PATH="$Z3_DIR/build/include/" cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=ON $RS3_DIR > /dev/null
make > /dev/null

# Build release and generate documentation

echo "[*] Building release"

mkdir -p $RELEASE_BUILD
cd $RELEASE_BUILD
CMAKE_PREFIX_PATH="$Z3_DIR/build" CMAKE_INCLUDE_PATH="$Z3_DIR/build/include/" cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON $RS3_DIR > /dev/null
make > /dev/null

echo "[*] Generating documentation"
make docs > /dev/null 2> /dev/null

# Symlink results

echo "[*] Symlinking"

mkdir -p $RS3_LIBS_DIR
link $RS3_LIBS_DIR/librs3d.so $DEBUG_BUILD/lib/librs3d.so
link $RS3_LIBS_DIR/librs3.so $RELEASE_BUILD/lib/librs3.so

link $RS3_INCLUDE_DIR $RS3_DIR/include/
link $RS3_EXAMPLES_DEBUG_DIR $DEBUG_BUILD/bin/
link $RS3_EXAMPLES_RELEASE_DIR $RELEASE_BUILD/bin/
link $RS3_DOCS_DIR $RELEASE_BUILD/docs/html/
