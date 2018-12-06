#!/bin/bash
pip install -r requirements.txt
if [ ! -d "mininet" ]; then
    git clone git://github.com/mininet/mininet
    cd mininet
    git checkout -b 2.2.1
    cd ..
    mininet/util/install.sh -a
fi
if [ ! -d "pox" ]; then
    git clone http://github.com/noxrepo/pox
    git checkout betta
fi