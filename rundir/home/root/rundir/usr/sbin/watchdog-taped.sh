#!/bin/sh

while true; do
	sleep 1;
	pid=`pidof taped`;
	if [ "$pid" == "" ];then
		echo "`date`: taped is dead" >> /tmp/watch-dog-taped.log;
		/home/root/rundir/usr/sbin/taped &
	fi
done
