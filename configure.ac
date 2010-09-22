#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_CONFIG_SRCDIR([src/SS5Main.c])
AC_CONFIG_HEADER([include/config.h])

OS=`uname -s`

if test "$OS" = "FreeBSD"; then
   lib_path_base="/usr/local/lib"
   conf_path_base="/usr/local/etc/opt"
   bin_path_base="/usr/local/sbin"
   doc_path_base="/usr/local/share/doc"
   man_path_base="/usr/share/man"
else
   lib_path_base="/usr/lib"
   conf_path_base="/etc/opt"
   bin_path_base="/usr/sbin"
   doc_path_base="/usr/share/doc"
   man_path_base="/usr/share/man"
fi;

log_path_base="/var/log/ss5"
trc_path_base="/var/log/ss5"

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lldap':
AC_CHECK_LIB([ldap], [main])
# FIXME: Replace `main' with a function in `-lpam':
AC_CHECK_LIB([pam], [main])
# FIXME: Replace `main' with a function in `-lpam_misc':
AC_CHECK_LIB([pam_misc], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])
# FIXME: Replace `main' with a function in `-ssl':
AC_CHECK_LIB([ssl], [main])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
# Checks for OS
if (test "$OS" != "SunOS") && (test "$OS" != "FreeBSD"); then
  AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h \
  security/pam_misc.h security/pam_appl.h],,[AC_MSG_ERROR(*** Some of the headers weren't found ***)])
else
  AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])
fi;


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa memset select socket strdup strtol])

# Arguments for compiling
#
AC_ARG_WITH(debug,          [  --with-debug]              Turn on debugging flags,                        [if test "$withval" == "yes"; then EXTRA_CFLAGS="$EXTRA_CFLAGS -ggdb -Wall -Wextra -pedantic -fno-strict-aliasing " ; else EXTRA_CFLAGS="" ;  fi])

AC_ARG_WITH(epollio,          [  --with-epollio]            Turn on EPOLL IO,                        [if test "$withval" == "yes"; then EXTRA_CFLAGS="$EXTRA_CFLAGS -D EPOLL_IO " ; else EXTRA_CFLAGS="" ;  fi])

AC_ARG_WITH(gssapi,         [  --with-gssapi]             Turn on gssapi support,              [gssapi="$withval"], [gssapi="no"])
  if test "$gssapi" != "no"; then 
    if test "$OS" = "SunOS"; then
      EXTRA_LIBS=" -lgss ";
      AC_CHECK_LIB([gss], [main])
    else
      AC_CHECK_LIB([gssapi], [main],[EXTRA_LIBS=" -lgssapi "],[])
      AC_CHECK_LIB([gssglue], [main],[EXTRA_LIBS=" -lgssglue "],[])
    fi;

    EXTRA_CFLAGS="$EXTRA_CFLAGS -DSS5_USE_GSSAPI ";
  fi;

AC_ARG_WITH(mysql,         [  --with-mysql]             Turn on mysql support,              [mysql="$withval"], [mysql="no"])
  if test "$mysql" != "no"; then 
    EXTRA_LIBS="$EXTRA_LIBS `mysql_config --libs`";

    EXTRA_CFLAGS="$EXTRA_CFLAGS -DSS5_USE_MYSQL ";
  fi;

AC_ARG_WITH(configfile,     [  --with-configfile=val]     Set the location of config file,     [SS5_CONFIG_FILE="$withval"]; AC_DEFINE_UNQUOTED(SS5_CONFIG_FILE, "$withval"))

AC_ARG_WITH(passwordfile,   [  --with-passwordfile=val]   Set the location of password file,   [SS5_PASSWORD_FILE="$withval"]; AC_DEFINE_UNQUOTED(SS5_PASSWORD_FILE, "$withval"))

AC_ARG_WITH(logfile,        [  --with-logfile=val]        Set the location of log file,        [SS5_LOG_FILE="$withval"]; AC_DEFINE_UNQUOTED(SS5_LOG_FILE, "$withval"))

AC_ARG_WITH(profilepath,    [  --with-profilepath=val]    Set the location of profile path,    [SS5_PROFILE_PATH="$withval"]; AC_DEFINE_UNQUOTED(SS5_PROFILE_PATH, "$withval"))

AC_ARG_WITH(libpath,        [  --with-libpath=val]        Set the location of ss5 modules,     [SS5_LIB_PATH="$withval"]; [lib_path_base="$withval"]; AC_DEFINE_UNQUOTED(SS5_LIB_PATH, "$withval"))

AC_ARG_WITH(tracepath,      [  --with-tracepath=val]      Set the location of ss5 trace files, [SS5_TRACE_PATH="$withval"]; AC_DEFINE_UNQUOTED(SS5_TRACE_PATH, "$withval"))

AC_ARG_WITH(defaultaddr,    [  --with-defaultaddr=val]    Set default bind address,            [SS5_DEFAULT_ADDR="$withval"]; AC_DEFINE_UNQUOTED(SS5_DEFAULT_ADDR, "$withval"))

AC_ARG_WITH(defaultport,    [  --with-defaultport=val]    Set default bind port,               [SS5_DEFAULT_PORT="$withval"]; AC_DEFINE_UNQUOTED(SS5_DEFAULT_PORT, "$withval"))

AC_ARG_WITH(defaultuser,    [  --with-defaultuser=val]    Set default user process,            [SS5_DEFAULT_USER="$withval"]; AC_DEFINE_UNQUOTED(SS5_DEFAULT_USER, "$withval"))


# Arguments for installing
#
AC_ARG_WITH(confpathbase,   [  --with-confpathbase=val]   Set install location of ss5 config files, [conf_path_base="$withval"])
AC_ARG_WITH(binpathbase,    [  --with-binpathbase=val]    Set install location of ss5 binary files, [bin_path_base="$withval"])
AC_ARG_WITH(docpathbase,    [  --with-docpathbase=val]    Set install location of ss5 doc files,    [doc_path_base="$withval"])
AC_ARG_WITH(manpathbase,    [  --with-manpathbase=val]    Set install location of ss5 man files,    [man_path_base="$withval"])
AC_ARG_WITH(logpathbase,    [  --with-logpathbase=val]    Set install location of ss5 log files,    [log_path_base="$withval"])
AC_ARG_WITH(tracepathbase,  [  --with-tracepathbase=val]  Set install location of ss5 trc files,    [trc_path_base="$withval"])


# Checks for OS
if test "$OS" = "Linux"; then
   CFLAGS="$CFLAGS -DLINUX -D_FILE_OFFSET_BITS=64"
   LIBS="-rdynamic -ldl -lssl -lldap -lpam -lpam_misc"
fi;
if test "$OS" = "SunOS"; then
   CFLAGS="$CFLAGS -DSOLARIS -fPIC -O2 -L/usr/local/lib -R/usr/local/lib"
   LIBS="-lsocket -lnsl -lssl -ldl -lldap -lpam"
fi;
if test "$OS" = "FreeBSD"; then
   CFLAGS="$CFLAGS -DFREEBSD -pthread -export-dynamic -I/usr/local/include"
   LIBS="-lpam -lldap -lc -L /usr/local/lib"
   CPP="g++"
fi;

AC_SUBST(CFLAGS)
AC_SUBST(LIBS)
AC_SUBST(EXTRA_CFLAGS)
AC_SUBST(EXTRA_LIBS)
AC_SUBST(SS5_CONFIG_FILE)
AC_SUBST(SS5_PASSWORD_FILE)
AC_SUBST(SS5_PROFILE_PATH)
AC_SUBST(SS5_LIB_PATH)
AC_SUBST(SS5_TRACE_PATH)
AC_SUBST(SS5_LOG_FILE)
AC_SUBST(SS5_DEFAULT_ADDR)
AC_SUBST(SS5_DEFAULT_PORT)
AC_SUBST(SS5_DEFAULT_USER)

AC_SUBST(lib_path_base)
AC_SUBST(conf_path_base)
AC_SUBST(bin_path_base)
AC_SUBST(doc_path_base)
AC_SUBST(man_path_base)
AC_SUBST(log_path_base)
AC_SUBST(trc_path_base)
AC_SUBST(OS)

AC_CONFIG_FILES([Makefile]
[modules/Makefile]
[modules/mod_authen/Makefile:build/mod_top.mk:modules/mod_authen/Makefile.in:build/mod_bot.mk]
[modules/mod_author/Makefile:build/mod_top.mk:modules/mod_author/Makefile.in:build/mod_bot.mk]
[modules/mod_balance/Makefile:build/mod_top2.mk:modules/mod_balance/Makefile.in:build/mod_bot2.mk]
[modules/mod_bandwidth/Makefile:build/mod_top.mk:modules/mod_bandwidth/Makefile.in:build/mod_bot.mk]
[modules/mod_dump/Makefile:build/mod_top.mk:modules/mod_dump/Makefile.in:build/mod_bot.mk]
[modules/mod_filter/Makefile:build/mod_top.mk:modules/mod_filter/Makefile.in:build/mod_bot.mk]
[modules/mod_log/Makefile:build/mod_top.mk:modules/mod_log/Makefile.in:build/mod_bot.mk]
[modules/mod_proxy/Makefile:build/mod_top.mk:modules/mod_proxy/Makefile.in:build/mod_bot.mk]
[modules/mod_socks4/Makefile:build/mod_top.mk:modules/mod_socks4/Makefile.in:build/mod_bot.mk]
[modules/mod_socks5/Makefile:build/mod_top.mk:modules/mod_socks5/Makefile.in:build/mod_bot.mk]
[modules/mod_statistics/Makefile:build/mod_top2.mk:modules/mod_statistics/Makefile.in:build/mod_bot2.mk]
[common/Makefile]
[src/Makefile]
)
AC_OUTPUT
