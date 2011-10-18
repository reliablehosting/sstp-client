sbin_PROGRAMS   = sstpc
sstpc_CFLAGS	= -I$(top_srcdir)/include -DSSTP_RUNTIME_DIR='"$(SSTP_RUNTIME_DIR)"'
sstpc_LDADD	    =       \
    libsstp-log/libsstp_log.la \
    libsstp-api/libsstp_api.la \
    libsstp-compat/libsstp_compat.la

sstpc_SOURCES =         \
    sstp-client.c       \
    sstp-option.c       \
    sstp-stream.c       \
    sstp-packet.c       \
    sstp-pppd.c         \
    sstp-util.c         \
    sstp-cmac.c         \
    sstp-buff.c         \
    sstp-http.c         \
    sstp-task.c         \
    sstp-event.c        \
    sstp-state.c        \
    sstp-chap.c         \
    sstp-fcs.c

noinst_HEADERS  =       \
    sstp-buff.h         \
    sstp-client.h       \
    sstp-chap.h         \
    sstp-cmac.h         \
    sstp-event.h        \
    sstp-fcs.h          \
    sstp-http.h         \
    sstp-option.h       \
    sstp-packet.h       \
    sstp-pppd.h         \
    sstp-private.h      \
    sstp-state.h        \
    sstp-stream.h       \
    sstp-task.h         \
    sstp-util.h
