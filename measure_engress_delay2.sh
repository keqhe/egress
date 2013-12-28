#! 
#clear
ps aux | grep -ie flowvisor | awk '{print $2}' | xargs kill -9
ps aux | grep -ie controller | awk '{print $2}' | xargs kill -9
ps aux | grep -ie pfsend | awk '{print $2}' | xargs kill -9
#ps aux | grep -ie pfcount | awk '{print $2}' | xargs kill -9
ps aux | grep -ie sniffer | awk '{print $2}' | xargs kill -9 
#start pox controller to clear the table and insert a default drop rule
#./pox/pox.py samples.l2_test
sleep 3

#start pfcount, read the buffer
#../pf_ring/userland/examples/pfcount -i dna1 &
#./simplesniffer eth2 &

#sleep 8
#kill the receiver
#ps aux | grep -ie sniffer | awk '{print $2}' | xargs kill -9
#sleep 3
#start the pfcount here for capture
#../pf_ring/userland/examples/pfcount -i dna1 -n 3 -g 3 -a & 

#sleep 5


#start pfsend
../pf_ring/userland/examples/pfsend -f flows.pcap -i eth1 -n 0 -r 1 &

sleep 10
#start controller
./pox/pox.py samples.l2_modification_proactive_priority
#wait for everying to be running and connected successfully
sleep  20

#wait some time before we close the experiments
#do a math
#sleep 300

# close the measurement session
ps aux | grep -ie flowvisor | awk '{print $2}' | xargs kill -9
ps aux | grep -ie controller | awk '{print $2}' | xargs kill -9
ps aux | grep -ie pfsend | awk '{print $2}' | xargs kill -9
ps aux | grep -ie sniffer | awk '{print $2}' | xargs kill -9
ps aux | grep -ie pox | awk '{print $2}' | xargs kill -9
#process the recorded file and get the delay caculation
export PATH=/usr/local/bro/bin/:$PATH
#python bro_trace.py
#python parse_control.py

