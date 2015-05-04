#!/bin/bash

REMOTE_HOSTNAME="staging.voip.lifeisbetteron.com"
NF_Q=10

WAN_IP="`ifconfig wlan0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
LAN_IP="`ifconfig eth0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://'`"
SBC_IP="`dig +short $REMOTE_HOSTNAME`"

echo ""
echo "       # # # # # # # # # # # # # # # # # # # # # # # # #"
echo "       # prepare IPTABLE to intercept and send traffic #"
echo "       # to the Netfilter Queue using IP tables.       #"
echo "       # # # # # # # # # # # # # # # # # # # # # # # # #"

echo "       remote host is : $REMOTE_HOSTNAME"
echo "       netfilter queue ID : $NF_Q"
echo "       LAN IP : $LAN_IP"
echo "       WAN IP : $WAN_IP"

echo ""
echo " ## display all you related firewal rules:"
echo ""
echo " sudo iptables -L -v -n"
echo ""
echo " ## flushing rules:"
echo " sudo iptables -F"


if [ -n "$LAN_IP" ]
then
	echo ""
	echo " ## disrupting traffic sent trough LAN interface:"
	echo ""
	echo " sudo iptables -A OUTPUT -s $LAN_IP -d $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
	echo ""
	echo " ## disrupting traffic received trough LAN interface:"
	echo ""
	echo " sudo iptables -A INPUT -d $LAN_IP -s $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
fi

if [ -n "$WAN_IP" ]
then
	echo ""
	echo " ## disrupting traffic sent trough WAN interface:"
	echo ""
	echo " sudo iptables -A OUTPUT -s $LAN_IP -d $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
	echo ""
	echo " ## disrupting traffic received trough WAN interface:"
	echo ""
	echo " sudo iptables -A INPUT -d $LAN_IP -s $SBC_IP -p all -j NFQUEUE --queue-num $NF_Q"
fi

echo ""
echo " ## starting disruptor:"
echo ""
echo " sudo ./disruptor -h"

echo
