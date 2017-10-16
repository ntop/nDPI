# Ubuntu steps - realease 14.04 
#
# It's *default* in 15.x or greater Ubuntu realeases
#
# - Require kernel 4.2 for act_connmark
# - Require iproute2 4.1.1
#
# 1. Update linux kernel
#     apt-get install linux-image-4.2.0-27-generic
#     apt-get install linux-headers-4.2.0-27
#     apt-get install linux-headers-4.2.0-27-generic
#     ln -sf /usr/src/linux-headers-4.2.0-27 /lib/modules/4.2.0-27-generic/build
#
# 2. Update iproute2 (4.1.1 version)
#     wget http://launchpadlibrarian.net/214987092/iproute2_4.1.1-1ubuntu1_amd64.deb
#     dpkg --install iproute2_4.1.1-1ubuntu1_amd64.deb
#
# 3. Rebuild ndpi-netfilter
#

# Using ifb interface to shape ingress flow
modprobe ifb
ifconfig ifb0 up

# Root qdisc
tc qdisc del dev ifb0 root 2> /dev/null
tc qdisc del dev eth0 ingress 2>/dev/null
/sbin/tc qdisc add dev eth0 ingress handle ffff:
/sbin/tc qdisc add dev ifb0 root handle 101:0 htb default ffff

# Interface rate
/sbin/tc class add dev ifb0 parent 101:0 classid 101:1 htb rate 100Mbit

# Default (101:ffff) and tcp traffic (101:2)
/sbin/tc class add dev ifb0 parent 101:1 classid 101:ffff htb prio 4 rate 45Mbit ceil 98Mbit  burst 20k cburst 20k
/sbin/tc class add dev ifb0 parent 101:1 classid 101:2 htb prio 3 rate 25Mbit ceil 90Mbit  burst 20k cburst 20k

# Web traffic (101:3) and youtube (101:4)
/sbin/tc class add dev ifb0 parent 101:1 classid 101:3 htb prio 2 rate 28Mbit ceil 90Mbit  burst 20k cburst 20k
/sbin/tc class add dev ifb0 parent 101:1 classid 101:4 htb prio 1 rate 2Mbit ceil 2Mbit  burst 5k cburst 5k

# Leaf qdisc 
/sbin/tc qdisc add dev ifb0 parent 101:ffff handle 803 pfifo 
/sbin/tc qdisc add dev ifb0 parent 101:2 handle 804 sfq divisor 256
/sbin/tc qdisc add dev ifb0 parent 101:3 handle 805 sfq divisor 256
/sbin/tc qdisc add dev ifb0 parent 101:4 handle 806 sfq divisor 256


# Firewall marks
# Flush mangle rules
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -N qosmark
iptables -t mangle -A qosmark -j CONNMARK --restore-mark
iptables -t mangle -A qosmark -m mark --mark 0x0 -j MARK --set-mark 0xffff
iptables -t mangle -A qosmark -m mark --mark 0x104 -j RETURN
iptables -t mangle -A qosmark -m connbytes --connbytes-dir both --connbytes-mode packets --connbytes 10 -j RETURN

# - Tcp and web traffic
iptables -t mangle -A qosmark -p tcp -j MARK --set-mark 0x102
iptables -t mangle -A qosmark -m multiport -p tcp --sport 80,443,8080 -j MARK --set-mark 0x103
iptables -t mangle -A qosmark -m multiport -p tcp --dport 80,443,8080 -j MARK --set-mark 0x103

# - NDPI traffic
iptables -t mangle -A qosmark -m ndpi --facebook -j MARK --set-mark 0x104
iptables -t mangle -A qosmark -m ndpi --youtube -j MARK --set-mark 0x104


# Mark rules
iptables -t mangle -A PREROUTING -j qosmark
iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark
iptables -t mangle -A OUTPUT -j qosmark


# tc filters
tc filter add dev ifb0 parent 101:0 protocol ip handle 0x102 fw flowid 101:2
tc filter add dev ifb0 parent 101:0 protocol ip handle 0x103 fw flowid 101:3
tc filter add dev ifb0 parent 101:0 protocol ip handle 0x104 fw flowid 101:4

# mirroring eth0 packets to ifb interface (shape ingress flow)
[ -f "/lib/modules/$(uname -r)/kernel/net/sched/act_connmark.ko" ] && cmd="action connmark" || cmd="action xt -j CONNMARK --restore-mark"
tc filter add dev eth0 parent ffff: protocol all prio 1 u32 match u32 0 0 $cmd action mirred egress redirect dev ifb0

#tc filter add dev eth0 parent ffff: protocol ip handle 0x104 fw action xt -j MARK --set-mark 0x104 action mirred egress redirect dev ifb0
