
cat /proc/sys/net/ipv4/forwarding 
cat /proc/sys/net/ipv4/conf/br-lan/forwarding 
cat /proc/sys/net/ipv4/conf/pppoe-wan/forwarding 


iptables -A INPUT -p tcp --dport 26633 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 26633 -j ACCEPT

#iptables -t nat -A PREROUTING -i eth0 -p tcp --dport $srcPortNumber -j REDIRECT --to-port $dstPortNumbe
#iptables -t nat -I PREROUTING --src $SRC_IP_MASK --dst $DST_IP -p tcp --dport $portNumber -j REDIRECT --to-ports $rediectPort

iptables -t nat -A PREROUTING -p tcp --dport 63306 -j DNAT --to-destination 192.168.16.226:50648
iptables -t nat -A POSTROUTING -d 192.168.16.226 -p tcp --dport 50648 -j SNAT --to 192.168.16.1

iptables -t nat -L PREROUTING -n --line-numbers -v
iptables -t nat -L POSTROUTING -n --line-numbers -v

iptables -t nat -L -n -v
iptables-save

#允许特定转发
iptables -N MINIUPNPD
iptables -I FORWARD -i pppoe-wan -o br-lan -j MINIUPNPD
#DNAT端口映射
iptables -t nat -N MINIUPNPD
iptables -t nat -I PREROUTING -i pppoe-wan -j MINIUPNPD

