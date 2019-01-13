
# get topdir
TOPDIR=/home/root/rundir/
PERL=${TOPDIR}/usr/bin/lua SRCDIR=/ /home/root/rundir/usr/sbin/lighttpd -f /home/root/rundir/etc/lighttpd.conf -m ${TOPDIR}/usr/lib
