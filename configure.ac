AC_INIT([disruptor],[0.0.1],[jchavanton@gmail.com])
AC_CONFIG_FILES([Makefile])


# verify the presence and version of Net filter queue
PKG_CHECK_MODULES([NET_FILTER_QUEUE], libnetfilter_queue >= 0.0.1, nfq_found=yes)
NET_FILTER_QUEUE_VERSION=`$PKG_CONFIG --modversion libnetfilter_queue`

 [Define if _doprnt exists.])])

# if $NET_FILTER_QUEUE_VERSION < 1; then
#  echo $NET_FILTER_QUEUE_VERSION
#else
# echo " ${NET_FILTER_QUEUE_VERSION} test"
# fi

AC_OUTPUT
