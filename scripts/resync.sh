#!/bin/bash
sshpass -p "frenetic" rsync -av -e ssh --exclude='*.ova' --exclude='wireshark/*' --exclude='ej/*' /home/sebastian/git/Datacenter/ frenetic@192.168.56.3:~/Datacenter/
sshpass -p "frenetic" rsync -av -e ssh /home/sebastian/git/Datacenter/src/controller.py frenetic@192.168.56.3:~/pox/ext/
sshpass -p "frenetic" rsync -av -e ssh /home/sebastian/git/Datacenter/src/firewall.py frenetic@192.168.56.3:~/pox/ext/
sshpass -p "frenetic" rsync -av -e ssh /home/sebastian/git/Datacenter/src/ecmp_table.py frenetic@192.168.56.3:~/pox/ext/
sshpass -p "frenetic" rsync -av -e ssh /home/sebastian/git/Datacenter/src/launch.py frenetic@192.168.56.3:~/pox/ext/


