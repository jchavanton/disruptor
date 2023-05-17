# Disruptor
 Network impairment server (generating problems on RTP streams : latency, delay, jitter)
 
 This tool can be used anywhere with netfilter and iptables.
 This is can be very handy when you need to test how an RTP application behaves when facing problems, using scenarios the same problems can be reproduced many times.
 
### install
```
apt-get update
apt-get install build-essential libnetfilter-queue-dev
./configure
make
```

### configure firewall
This script will ouput examples of iptables command to pass traffic to the disruptor using netfilter queues
```
./prepare_firewall.sh server.domain.com
```
You may have to edit the script if your interfaces names are not `wlan0` and/or `eth0`

### start the disruptor
```
./disruptor -h
-d daemonize
-q nfq queue id
-f scenario file name
-l log level: 0=error, 1=info, 2=notice, 3=debug
```

### Examples
```
./prepare_firewall.sh webrtc.server.com 10.0.0.243
# execute the returned iptable commands
sudo OUTPUT -d 54.13.17.12 -p all -j NFQUEUE --queue-num 10
# run the disruptor
sudo ./disruptor -f scenario.xml -l 3
```

### XML scenario files example ###
```
<?xml version="1.0"?>
<scenario>
       <period duration="5"><action name="loss" rand="10"/></period>
       <period duration="5"><action name="loss" rand="10"/></period>
</scenario>
```

####  action: jitter ####
```
burst_max : maximum random size of delayed burst in packets
interval_max : maximum random  interval between burst in packets
burst_size : size of delayed burst in packets
interval_size : interval between burst in packets
outoforder : burst out of order
```

#### action: loss ####
```
rand : percentage of losses to apply on the stream
```

#### action: burst_loss ####
```
rand : random interval in packets between occurrences
max : random size of the burst (consecutive packets) loss
```

#### action: loss_rtcp ####
```
rand : percentage loss of RTCP packets
```


