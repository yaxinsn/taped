
# get topdir
TOPDIR=/home/root/rundir/
PERL=${TOPDIR}/usr/bin/lua SRCDIR=/ ~/rundir/usr/sbin/lighttpd -f ~/rundir/etc/lighttpd.conf -m ${TOPDIR}/usr/lib
