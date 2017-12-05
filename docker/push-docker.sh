#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

if [ "$DOCKER_REPO" = "" ]; then
  echo "Missing DOCKER_REPO environment variable"
  exit 1
fi

DOCKER_IMAGE=${DOCKER_IMAGE:-dashevo/dashcore}
DOCKER_TAG=${DOCKER_TAG:-develop}

docker tag $DOCKER_IMAGE:$DOCKER_TAG $DOCKER_REPO/$DOCKER_IMAGE:$DOCKER_TAG
docker push $DOCKER_REPO/$DOCKER_IMAGE:$DOCKER_TAG
docker rmi $DOCKER_REPO/$DOCKER_IMAGE:$DOCKER_TAG
