srcdir=.
top_srcdir=..
top_builddir=..

COMMONOBJ  = SS5OpenLdap.o SS5Radius.o SS5MySql.o


CFLAGS=-g -O2 -DLINUX -D_FILE_OFFSET_BITS=64 -I . -I ../include   -ggdb -Wall -Wextra -pedantic -fno-strict-aliasing  -D EPOLL_IO  -DSS5_USE_GSSAPI  -DSS5_USE_MYSQL  -fPIC
SRVCFLAGS=-g -O2 -DLINUX -D_FILE_OFFSET_BITS=64 -I . -I ../include  -ggdb -Wall -Wextra -pedantic -fno-strict-aliasing  -D EPOLL_IO  -DSS5_USE_GSSAPI  -DSS5_USE_MYSQL 

LIBS = -lpthread -rdynamic -ldl -lssl -lldap -lpam -lpam_misc  -lgssglue  -rdynamic -L/usr/lib/mysql -lmysqlclient -lz -lcrypt -lnsl -lm -L/usr/lib -lssl -lcrypto 

CC = gcc

all:	$(COMMONOBJ)


clean:
	rm -f $(COMMONOBJ)

distclean: clean
	rm -f Makefile
