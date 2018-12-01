#!/bin/bash
sshpass -p "frenetic" rsync -av -e ssh --exclude='*.ova' /home/sebastian/git/Datacenter/ frenetic@192.168.56.3:~/Datacenter/
sshpass -p "frenetic" rsync -av -e ssh /home/sebastian/git/Datacenter/controller.py firewall.py ecmp_table.py launch.py frenetic@192.168.56.3:~/pox/ext/


