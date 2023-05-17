#!/bin/bash

TARGET=$1
if [ "${TARGET}" == "" ]
then
	echo "$0 <destination hostname> <local IP>"
	exit
fi

LOCAL_IP=$2
if [ "${2}" == "" ]
then
	echo "$0 ${TARGET} <local IP>"
	exit
fi

REMOTE_HOSTNAME=$1
NF_Q=10
TARGET_IP="`dig +short $REMOTE_HOSTNAME`"
IP_FORWARD=`cat /proc/sys/net/ipv4/ip_forward`

echo ""
echo " # # # # # # # # # # # # # # # # # # # # # # # # #"
echo " # prepare IPTABLE to intercept and send traffic #"
echo " # to the Netfilter Queue using IP tables.       #"
echo " # # # # # # # # # # # # # # # # # # # # # # # # #"

echo " remote host is : $REMOTE_HOSTNAME"
echo " netfilter queue ID : $NF_Q"
echo " Local IP : $LOCAL_IP"
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
	echo " iptables -I FORWARD -s $TARGET_IP -p all -j NFQUEUE --queue-num 10"
	echo " iptables -I FORWARD -d $TARGET_IP -p all -j NFQUEUE --queue-num 10"
fi

if [ -n "$LOCAL_IP" ]
then
	echo ""
	echo " ## disrupting traffic sent trough interface:"
	echo " sudo iptables -A OUTPUT -s $LOCAL_IP -d $TARGET_IP -p all -j NFQUEUE --queue-num $NF_Q"
	echo ""
	echo " ## disrupting traffic received trough LAN interface:"
	echo " sudo iptables -A INPUT -d $LOCAL_IP -s $TARGET_IP -p all -j NFQUEUE --queue-num $NF_Q"
fi

echo ""
echo " ## starting disruptor:"
echo " sudo ./disruptor -h"

echo
