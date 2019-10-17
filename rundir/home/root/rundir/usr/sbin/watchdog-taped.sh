#!/bin/sh

while true; do
	sleep 1;
	local pid=`pidof taped`;
	if [ "$pidX" == "X" ];then
		echo "`date`: taped is dead" >> /tmp/watch-dog-taped.log;
		/home/root/rundir/usr/sbin/taped &
	fi
done
