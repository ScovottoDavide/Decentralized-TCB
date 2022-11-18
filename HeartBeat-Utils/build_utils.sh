#!/bin/bash

unset WAM_DIR
export WAM_DIR="/home/privateadm"

cd generateIndexesWAM
echo "Building Index files generator"
make &> /dev/null
cd ..

cd heartbeat_WAM
echo "Building heartbeat"
make &> /dev/null
cd ..

exit 1