#!/bin/sh

LOG_F="/home/root/network.log"
log()
{
	echo $@ >> /home/root/network.log
}
echo "start --------------" >> $LOG_F;
echo " param: $@" >>$LOG_F;

ifconfig br-lan
[ "$?" != "0" ] && brctl addbr br-lan

ifconfig eth0 0.0.0.0
brctl addif br-lan eth0
brctl addif br-lan eth1


ifconfig br-lan $1
ifconfig br-lan netmask $2
route delete default;
log "del default route ret $?" 
route add default gw $3;
log "add default route ret $?" 

ifconfig br-lan up

log "route info:"
route >>$LOG_F;

echo "end --------------" >> $LOG_F;

