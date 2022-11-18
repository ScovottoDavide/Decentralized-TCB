#!/bin/bash

if [ $#  -lt 1 ]; then
  echo "Illegal number of parameters"
  echo "Usage: ./build_utils.sh (WAM and iota.c installation directory)"
  exit 1
fi

if [[ -d "$1" ]]; then
   echo "it is a directory" &> /dev/null
else
   echo "Invalid path"
   exit -1
fi

unset WAM_DIR
export WAM_DIR=$1

cd generateIndexesWAM
echo "Building Index files generator"
make &> /dev/null
cd ..

cd heartbeat_WAM
echo "Building heartbeat"
make &> /dev/null
cd ..

exit 1