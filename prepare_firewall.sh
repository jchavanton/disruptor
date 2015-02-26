#!/bin/bash


echo "##"
echo "## prepare IPTABLE to intercept and send traffic to the Netfilter Queue using IP tables"
echo "##"

echo ""
echo "display all you related firewal rules:"
echo "## listing rules:"
echo "sudo iptables -L -v -n"
echo ""
echo "## flushing rules:"
echo "sudo iptables -F"

WAN_IP="`ifconfig wlan0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
LAN_IP="`ifconfig eth0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
SBC_IP="`dig +short staging.voip.lifeisbetteron.com`"

echo ""
echo "## disrupting traffic sent trough LAN interface:"
echo "sudo iptables -A OUTPUT -s $LAN_IP -d $SBC_IP -p all -j NFQUEUE --queue-num 10"
echo "## disrupting traffic received trough LAN interface:"
echo "sudo iptables -A INPUT -d $LAN_IP -s $SBC_IP -p all -j NFQUEUE --queue-num 10"

echo ""
echo "## disrupting traffic sent trough WAN interface:"
echo "sudo iptables -A OUTPUT -s $LAN_IP -d $SBC_IP -p all -j NFQUEUE --queue-num 10"
echo "# disrupting traffic reveived trough WAN interface:"
echo "sudo iptables -A INPUT -d $LAN_IP -s $SBC_IP -p all -j NFQUEUE --queue-num 10"

echo ""
echo "## starting disruptor:"
echo "sudo ./disruptor -h"

echo
