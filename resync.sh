#!/bin/bash
rsync -av -e ssh --exclude='*.ova' /home/sebastian/git/Datacenter/ frenetic@192.168.56.3:~/Datacenter/
