#!/bin/bash

if [ $#  -lt 1 ]; then
  echo "Illegal number of parameters"
  echo "Usage: ./generate_and_dispatch_indexes $(number of index files to generate) -- exclude the heartbeat node in the count"
  exit 1
fi

re='^[0-9]+$'
if ! [[ $1 =~ $re ]] ; then
    echo "error: Not a number"
    exit 1
fi

if [ $1 -le 0 ]; then
    echo "Number of index files must be greater than zero"
    exit 1
fi

# clean up already existing index files
rm heartbeat_WAM/heartbeat_write.json &> /dev/null
rm generateIndexesWAM/TPA_index_node* &> /dev/null
rm generateIndexesWAM/RA_index_node* &> /dev/null

# generate Indexes 
cd generateIndexesWAM
./WAM_generateIndexes $1
mv heartbeat_write.json ../heartbeat_WAM/
#for i in $(seq 1 $1); do
    #echo "--> Sending TPA_index_node$i and RA_index_node$i file to node"
    scp TPA_index_node1.json RA_index_node1.json pi@192.168.0.115:/etc/tc
    scp TPA_index_node2.json RA_index_node2.json pi@192.168.0.114:/etc/tc
    scp TPA_index_node3.json RA_index_node3.json pi@192.168.0.105:/etc/tc
    scp TPA_index_node4.json RA_index_node4.json pi@192.168.0.108:/etc/tc
#done
rm TPA_index_node* RA_index_node*

cd ..

echo "DONE"

#cd heartbeat_WAM && ./WAM_heartbeat