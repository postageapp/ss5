srcdir=.
top_srcdir=..
top_builddir=..

COMMONOBJ  = SS5OpenLdap.o SS5Radius.o SS5MySql.o


CFLAGS=-g -O2 -DLINUX -D_FILE_OFFSET_BITS=64 -I . -I ../include   -fPIC
SRVCFLAGS=-g -O2 -DLINUX -D_FILE_OFFSET_BITS=64 -I . -I ../include 

LIBS = -lpthread -rdynamic -ldl -lssl -lldap -lpam -lpam_misc  

CC = gcc

all:	$(COMMONOBJ)


clean:
	rm -f $(COMMONOBJ)

distclean: clean
	rm -f Makefile
