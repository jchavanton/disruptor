#!/bin/bash

# sudo iptables -A OUTPUT -s 192.168.1.3 -d 90.84.151.45 -p all -j NFQUEUE --queue-num 0
# sudo ./rtp_analyser -r 90.84.151.45 -e 192.168.1.3 -s 3


echo ""
echo "display all you related firewal rules:"
echo "sudo iptables -L -v -n"
echo ""

IP="`ifconfig wlan0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
SBC_IP="`dig +short staging.voip.lifeisbetteron.com`"

echo "sudo iptables -A OUTPUT -s $IP -d $SBC_IP -p all -j NFQUEUE --queue-num 10"
echo "sudo iptables -A INPUT -d $IP -s $SBC_IP -p all -j NFQUEUE --queue-num 10"
echo "sudo ./disruptor -q 10 -s 2 | grep random"

echo
