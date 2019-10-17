#!/bin/sh
TOPDIR="/home/root/rundir"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${TOPDIR}/lib/:${TOPDIR}/usr/lib/"
export PATH="/usr/bin:/usr/sbin:/bin:/sbin:${TOPDIR}/bin/:${TOPDIR}/sbin/:${TOPDIR}/usr/bin/:${TOPDIR}/usr/sbin"

LOG_F=/home/root/init.log

ulimit -c unlimited
echo "1" > /proc/sys/kernel/core_uses_pid

mkdir /home/root/core/
echo "/home/root/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern

echo "run it " >> /home/root/init.log
/home/root/rundir/usr/sbin/taped &
/home/root/rundir/sbin/start.sh &
/home/root/rundir/usr/sbin/watchdog-taped.sh &
if [ -e /etc/dropbear ];then
	ls /etc/dropbear -lht >>$LOG_F

else
mkdir /etc/dropbear
dropbearkey  -t rsa -f /etc/dropbear/dropbear_rsa_host_key
fi
dropbear &
