# disruptor
 generating problems on RTP streams : latency, delay, jitter
 
### install
 ```
 apt-get install  build-essential
 apt-get install libnetfilter-queue-dev
 ./configure
 make
 ```
### configure firewall
 This script will ouput examples of iptables command to pass traffic to the disruptor using netfilter queues
 ```
 ./prepare_firewall.sh
 ```
### start the disruptor
```
./disruptor -h
-q nfq queue id
-f scenario file name
-l log level: 0=error, 1=info, 2=notice, 3=debug
```
###  action jitter ###

burst_max : maximum random size of delayed burst in packets

interval_max : maximum random  interval between burst in packets

burst_size : size of delayed burst in packets

interval_size : interval between burst in packets

outoforder : burst out of order

### XML scenario files example
```
<?xml version="1.0"?>
<!--
     simulate jitter caused by "congestion" resulting in random delayed packets burst
     action: jitter
     rand: percentage of chances that a problem occurrence start at each packet
     max: maximum burst size in packets
     <action name="jitter" rand="50" max="200"/>

     simulate none
     action: none
     rand: percentage nones
-->
<scenario>
       <period duration="5"><action name="loss" rand="10"/></period>
       <period duration="5"><action name="loss" rand="10"/></period>
</scenario>
```
