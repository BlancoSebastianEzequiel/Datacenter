#!/bin/bash
C=$1
L=$2
if [ -z $C ]
then
    C=3
fi
if [ -z $L ]
then
    L=3
fi
sudo mn --custom src/topology.py --topo mytopo,levels=$L,clients=$C --mac --switch ovsk --controller remote