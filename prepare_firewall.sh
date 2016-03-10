#!/bin/bash

REMOTE_HOSTNAME=$1
NF_Q=10

WAN_IP="`ifconfig wlan0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
LAN_IP="`ifconfig eth0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
SBC_IP="`dig +short $REMOTE_HOSTNAME`"
IP_FORWARD=`cat /proc/sys/net/ipv4/ip_forward`

echo ""
echo " # # # # # # # # # # # # # # # # # # # # # # # # #"
echo " # prepare IPTABLE to intercept and send traffic #"
echo " # to the Netfilter Queue using IP tables.       #"
echo " # # # # # # # # # # # # # # # # # # # # # # # # #"

echo " remote host is : $REMOTE_HOSTNAME"
echo " netfilter queue ID : $NF_Q"
echo " LAN IP : $LAN_IP"
echo " WAN IP : $WAN_IP"
echo " ipv4/ip_forward: $IP_FORWARD"

echo ""
echo " ## display all you related firewal rules:"
echo " sudo iptables -L -v -n"
echo ""
echo " ## flushing rules:"
echo " sudo iptables -F"


if [  "$IP_FORWARD" == 1 ]
then
	echo ""
	echo " ## IP Forwarding found on the server, consider the following line :"
	echo " iptables -I FORWARD -s $SBC_IP -p all -j NFQUEUE --queue-num 10"
	echo " iptables -I FORWARD -d $SBC_IP -p all -j NFQUEUE --queue-num 10"
fi

if [ -n "$LAN_IP" ]
then
	echo ""
	echo " ## disrupting traffic sent trough LAN interface:"
	echo " sudo iptables -A OUTPUT -s $LAN_IP -d $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
	echo ""
	echo " ## disrupting traffic received trough LAN interface:"
	echo " sudo iptables -A INPUT -d $LAN_IP -s $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
fi

if [ -n "$WAN_IP" ]
then
	echo ""
	echo " ## disrupting traffic sent trough WAN interface:"
	echo " sudo iptables -A OUTPUT -s $LAN_IP -d $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
	echo ""
	echo " ## disrupting traffic received trough WAN interface:"
	echo " sudo iptables -A INPUT -d $LAN_IP -s $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
fi

echo ""
echo " ## starting disruptor:"
echo " sudo ./disruptor -h"

echo
