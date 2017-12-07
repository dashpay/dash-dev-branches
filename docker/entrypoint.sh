#!/usr/bin/env bash

DEFAULT_CONFIG_PATH=$HOME/.dashcore/dash.conf
PROVIDED_CONFIG_PATH=/dash/dash.conf

for i in $@; do
  if [[ $i =~ ^-[^=]+=.* ]]; then
    K=$(echo "$i" | sed 's/^\([^=]*\)=\(.*\)/\1/')
    V=$(echo "$i" | sed 's/^\([^=]*\)=\(.*\)/\2/')
    if [ "$K" == "-conf" ]; then
      PROVIDED_CONFIG_PATH="$(realpath $V)"
    fi
  fi
done

# copy config file to default location so that dash-cli works
if [ -f "$PROVIDED_CONFIG_PATH" -a "$DEFAULT_CONFIG_PATH" != "$PROVIDED_CONFIG_PATH" ]; then
  mkdir -p $HOME/.dashcore
  cp $PROVIDED_CONFIG_PATH $DEFAULT_CONFIG_PATH
fi

exec $@
