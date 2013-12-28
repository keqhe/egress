#clean the process if they are already running
ps aux | grep -ie flowvisor | awk '{print $2}' | xargs kill -9
ps aux | grep -ie controller | awk '{print $2}' | xargs kill -9
ps aux | grep -ie tcpdump | awk '{print $2}' | xargs kill -9
ps aux | grep -ie pktgen | awk '{print $2}' | xargs kill -9
ps aux | grep -ie pfcount | awk '{print $2}' | xargs kill -9
ps aux | grep -ie pfsend | awk '{print $2}' | xargs kill -9

