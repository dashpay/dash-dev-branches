#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-dashevo/dashcore}
DOCKER_TAG=${DOCKER_TAG:-develop}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
cp $BUILD_DIR/src/dashd docker/bin/
cp $BUILD_DIR/src/dash-cli docker/bin/
cp $BUILD_DIR/src/dash-tx docker/bin/

docker build -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
