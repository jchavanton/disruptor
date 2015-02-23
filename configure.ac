AC_INIT([disruptor],[0.0.1],[jchavanton@gmail.com])
AC_CONFIG_FILES([Makefile])


# verify the presence and version of Net filter queue
PKG_CHECK_MODULES([NET_FILTER_QUEUE], libnetfilter_queue,
	if $PKG_CONFIG --atleast-version=1.0.0 libnetfilter_queue; then
		echo "netfilter queue version:" `$PKG_CONFIG --modversion libnetfilter_queue`
	else
		AC_DEFINE(NFQ_V0)
		echo "old libnetfilter_queue version:" `$PKG_CONFIG --modversion libnetfilter_queue`
	fi
)

cp confdefs.h include/disruptor_config.h
AC_OUTPUT
