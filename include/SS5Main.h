  /* Socks Server 5
* Copyright (C) 2002 - 2006 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef SS5MAIN_H
#define SS5MAIN_H 1

#include <pthread.h>
#include <pwd.h>

#ifndef SOLARIS
#define _XOPEN_SOURCE
#endif

#include <time.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

#undef __FD_SETSIZE
#define __FD_SETSIZE 8192

#include <sys/select.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <grp.h>
#include <stdarg.h>

#ifdef SS5_USE_GSSAPI
#include <gssapi/gssapi.h>

#ifdef SOLARIS
#include <gssapi/gssapi_ext.h>
#else
#include <gssapi/gssapi_generic.h>
#endif

#endif


#include "config.h"

#ifdef LINUX
#include <linux/if.h>
#include <linux/if_ether.h>
#endif

#ifdef SOLARIS
#include <net/if.h>
#include <sys/sockio.h>
#endif

#ifdef FREEBSD
#include <sys/syslog.h>
#include <sys/param.h>
#include <net/if.h>
#include <net/if_dl.h>
#endif

/*
 * SS5 Title
 */
#define SS5_VERSION        "SS5 Version 3.8.2 - Release 6"
#define SS5_COPYRIGHT      "Copyright (C) 2002-2010 by Matteo Ricchetti - <matteo.ricchetti@libero.it>"

/*
* MACRO for epoll:
*/
#ifdef EPOLL_IO
#include <sys/epoll.h>
#define IFEPOLL(x)	x
#define IFSELECT(x)
#else
#define IFSELECT(x)	x
#define IFEPOLL(x)
#endif

/*
* MACRO for OS:
*/
#ifdef LINUX
#define IFLINUX(x)	x
#define IFSOLARIS(x)
#else
#define IFSOLARIS(x)	x
#define IFLINUX(x)
#endif

#ifdef LINUX
#define SS5_SEND_OPT           MSG_NOSIGNAL   
#else
#define SS5_SEND_OPT           0     
#endif

/*
* MACRO for options:
*/
#define THREADED()	 ( SS5SocksOpt.IsThreaded )
#define NOTTHREADED()	 ( !SS5SocksOpt.IsThreaded )

#define SYSLOG()	 ( SS5SocksOpt.Syslog )
#define VERBOSE()	 ( SS5SocksOpt.Verbose )
#define GSSAPI()	 ( ci->GssEnc != GSS_NO_ENC )
#define GSSINTEGRITY()	 ( ci->GssEnc != GSS_ENC_NOINT )
#define DEBUG()		 ( SS5SocksOpt.Debug )
#define BALANCE()	 ( SS5SocksOpt.IsBalance )
#define CONSOLE()	 ( SS5SocksOpt.IsConsole )
#define SS5SRV()	 ( SS5SocksOpt.IsSrvmgr )
#define DUMP()		 ( SS5SocksOpt.IsDump )
#define FILTER()	 ( SS5Facilities.Fixup[0] != '-' )
#define DISFILTER()	   SS5Facilities.Fixup[0] = '-';
#define ROUTE()		 ( SS5SocksOpt.IsRoute )
#define UPSTREAM()	 ( SS5SocksOpt.IsUpstream )
#define BANDWIDTH()	 ( SS5Facilities.Bandwidth )
#define BANDWIDTHXUSER() ( SS5Facilities.BandwidthXUser )

#define AUTHENFILE()      ( SS5SocksOpt.Authentication == FILE_AUTHENTICATION )
#define AUTHENEAP()       ( SS5SocksOpt.Authentication == EAP_AUTHENTICATION )
#define AUTHENPAM()       ( SS5SocksOpt.Authentication == PAM_AUTHENTICATION )
#define AUTHENRADIUS()    ( SS5SocksOpt.Authentication == RADIUS_AUTHENTICATION )
#define LDAPBASE() 	  ( SS5SocksOpt.LdapCriteria   == LDAP_BASE )
#define LDAPFILTER() 	  ( SS5SocksOpt.LdapCriteria   == LDAP_FILTER )
#define AUTHORFILE()      ( SS5SocksOpt.Profiling      == FILE_PROFILING )
#define AUTHORDIRECTORY() ( SS5SocksOpt.Profiling      == LDAP_PROFILING )
#define ISSOCKS4()	  ( SS5ClientInfo.Ver          == SOCKS4_VERSION )
#define ISSOCKS5()	  ( SS5ClientInfo.Ver          == SOCKS5_VERSION )
#define NOTMUTE()	  ( SS5SocksOpt.Mute           == ERR )

#define STREQ(x,y,z)	  !strncmp(x,y,z)
#define STRCASEEQ(x,y,z)  !strncasecmp(x,y,z)

/*
* MACRO for modules:
*/
#define MODBALANCING()  ( SS5Modules.mod_balancing_loaded  )
#define MODSTATISTICS() ( SS5Modules.mod_statistics_loaded )
#define MODBANDWIDTH()  ( SS5Modules.mod_bandwidth_loaded  )
#define MODDUMP()       ( SS5Modules.mod_dump_loaded       )
#define MODFILTER()     ( SS5Modules.mod_filter_loaded     )
#define MODSOCKS4()     ( SS5Modules.mod_socks4_loaded     )
#define NOTMODSOCKS4()  ( !SS5Modules.mod_socks4_loaded    )

#define LOGUPDATE()	SS5Modules.mod_logging.Logging(logString);

/*
* MACRO for general purpose:
*/
#define LOCKMUTEXCS()    pthread_mutex_lock  ( &CSMutex  );
#define UNLOCKMUTEXCS()  pthread_mutex_unlock( &CSMutex  );
#define LOCKMUTEXCA()    pthread_mutex_lock  ( &CAMutex  );
#define UNLOCKMUTEXCA()  pthread_mutex_unlock( &CAMutex  );
#define LOCKMUTEXCT()    pthread_mutex_lock  ( &CTMutex  );
#define UNLOCKMUTEXCT()  pthread_mutex_unlock( &CTMutex  );
#define LOCKMUTEXCO()    pthread_mutex_lock  ( &COMutex  );
#define UNLOCKMUTEXCO()  pthread_mutex_unlock( &COMutex  );
#define LOCKMUTEXPAM()   pthread_mutex_lock  ( &PAMMutex );
#define UNLOCKMUTEXPAM() pthread_mutex_unlock( &PAMMutex );
#define LOCKMUTEXBT()    pthread_mutex_lock  ( &BTMutex  );
#define UNLOCKMUTEXBT()  pthread_mutex_unlock( &BTMutex  );
#define LOCKMUTEXAC()    pthread_mutex_lock  ( &ACMutex  );
#define UNLOCKMUTEXAC()  pthread_mutex_unlock( &ACMutex  );
#define LOCKMUTEXAEC()    pthread_mutex_lock  ( &AECMutex  );
#define UNLOCKMUTEXAEC()  pthread_mutex_unlock( &AECMutex  );

#define STRSCAT(d,s)   d[sizeof(d)-1]='\0';l=strlen(d);for( i=0; i< (sizeof(d)-l-1) && s[i] != '\0'; i++){ d[l+i] = s[i];}; d[l+i] = '\0';

#define GETADDR(x,y,z)   y=0; for(i=0;i<4;i++) { y += ((ULINT)x[3-i+z] << (i*8)); };
#define GETPORT(x,y,z)   y=0; for(i=0;i<2;i++) { y += ((ULINT)x[2-i+z] << (i*8)); };

#define SETPORT(x,y,z)   for(i=0;i<2;i++) { x[i+z]=  (y & (0x00FF << (i*8))) >> (i*8); };
#define SETADDR(x,y,z)   for(i=0;i<4;i++) { x[i+z]=  (y & (0x000000FF << (i*8))) >> (i*8); };
#define SETADDR_R(x,y,z) for(i=0;i<4;i++) { x[3-i+z]=(y & (0x000000FF << (i*8))) >> (i*8); };
#define SETPORT_R(x,y,z) for(i=0;i<2;i++) { x[1-i+z]=(y & (0x00FF << (i*8))) >> (i*8); };

#ifdef LINUX
#define ERRNO(p)        { char s[128]; strerror_r(errno,s,sizeof(s)); snprintf(logString,        \
                          sizeof(logString) - 1,"[%u] [ERRO] $%s$: (%s).",p,__func__,s); LOGUPDATE() }
#else
#define ERRNO(p)        { snprintf(logString,sizeof(logString) - 1,"[%u] [ERRO] $%s$: (%s)."     \
                          ,p,__func__,strerror(errno)); LOGUPDATE() }
#endif

#define ERRNOPAM(p,h,e) { snprintf(logString,sizeof(logString) - 1,"[%u] [ERRO] $%s$: (%s).",    \
                          p,__func__,pam_strerror( h, e)); LOGUPDATE() }

#define ERRNOLDAP(p,r)  { snprintf(logString,sizeof(logString) - 1,"[%u] [ERRO] $%s$: (%s).",    \
                          p,__func__,ldap_err2string(r)); LOGUPDATE() }

/*
* Socks RFC definitions:
* ------------------------------------------------------------------------------------
*
*/

enum VER_SS5       { SOCKS4_VERSION = 4,
	             SOCKS5_VERSION = 5 };

enum METHOD_SS5    { NOAUTH     = 0,
	     	     GSSAPI     = 1,
	     	     USRPWD     = 2,
	     	     S_USER_PWD = 0x21,          /* RFC by Raffaele De Lorenzo (raffaele.delorenzo@libero.it) */
	     	     FAKEPWD    = 254,
	     	     NOMETHOD   = 255 };

enum COMMAND_SS5   { CONNECT       = 1,
	             BIND          = 2,
	             UDP_ASSOCIATE = 3 };

enum ADDRTYPE_SS5  { IPV4   = 1,
	             DOMAIN = 3,
	             IPV6   = 4 };

/*
* SS5 DEFININITION
* ------------------------------------------------------------------------------------
*
*/

#define DISPLAY			0
#define CFGFILE			1

#define ONLINE                  0
#define OFFLINE                 1

#define CONTINUE                0
#define EXIT                    1
#define THREAD_EXIT             0

#define LOAD_CONFIG             2
#define RELOAD_CONFIG           1
#define PARSE_CONFIG            0

#define MASTER			1
#define SLAVE			2
#define ALONE			3

#define SRC_ROUTE		0
#define DST_ROUTE		1

#define SOCKS5_PORT             1080    /* Default socks port */
#define DATABUF                 1460    /* MTU - (header IP + header TCP) */
#define MAXIF                   2048    /* Max number of network interfaces */
#define MAXPREFORKPROCS         5000    /* Max number of preforked processes */
#define MAXPREFORKPROCLIFE      2048    /* Max number of requests a preforked process can servs */
#define MAXPEERS                  12    /* Max number of network interfaces */
#define MAXPPATHLEN      4096

enum ERR_SS5 { 
  ERR = 0,
  OK  = 1
};

typedef int INT;
typedef unsigned int UINT;
typedef unsigned long int ULINT;

struct _SS5ClientInfo{
  UINT Ver;
  UINT NMeth;
  UINT NoAuth;
  UINT BasicAuth;
  UINT GssApiAuth;
  UINT SecureBasicAuth;
  UINT Method;

  int  Socket;
  int  appSocket;
  char SrcAddr[16];
  UINT SrcPort;
  UINT GssEnc;

  int udpSocket;
  char udpSrcAddr[16];
  UINT udpSrcPort;
  UINT Stream;

  char Username[64];
  char Password[64];

  char Request[1024];             /* Basic request packet  */
  char Response[2];               /* Basic response packet */


#ifdef SS5_USE_GSSAPI
  gss_ctx_id_t GssContext;
#endif

  /* Radius info */
  struct sockaddr_in framedRoute;
  unsigned char radiusTmp[16];
  UINT sid;
  ULINT sessionTime;
  ULINT oPacket,iPacket;
};

struct _SS5RequestInfo {
  UINT Ver;
  UINT Cmd;
  UINT Rsv;
  UINT ATyp;
  char DstAddr[64];
  UINT DstPort;

  UINT udpRsv;
  UINT udpFrag;
  UINT udpATyp;
  char udpDstAddr[64];
  UINT udpDstPort;

  ULINT upDstAddr;
  UINT upDstPort;
  UINT upSocksVer;
};

struct _SS5DumpInfo {
  UINT DumpMode;
};

struct _SS5ParseConfFile {
  char srcAddr[64];      /* Source address buffer         */
  char srcPort[16];      /* Source port buffer            */
  char dstAddr[64];      /* Destination address buffer    */
  char dstPort[16];      /* Destination port buffer       */
  char socksMeth[1];     /* Socks method buffer           */
  char fixup[16];        /* Fixup buffer                  */
  char user[256];        /* User name buffer              */
  char group[256];       /* Group name buffer             */
  char groupPath[256];   /* Grouppath name buffer         */
  char bandwidth[16];    /* Bandwidth buffer              */
  char lCon[6];          /* N connections buffer          */
  char expDate[10];      /* Expiration date buffer        */
  char pxyAddr[16];      /* Upstream proxy address buffer */
  char pxyPort[6];       /* Upstream proxy port buffer    */
  char upSocksV[1];      /* Upstream socks version buffer */
  char dumpDir[3];       /*                               */
  char real[16];         /* Real server address buffer    */
  char vid[6];           /* Virtual identifier buffer     */
  char srcIf[16];        /* Source interface buffer       */
  char routeDir[1];      /* Route direction buffer        */
  char slogFacil[32];    /* Syslog facility and level     */
};

struct _SS5Facilities {
  char Fixup[16];                    /* Fixup               */
  char Group[256];                   /* User groups         */
  ULINT Bandwidth;       /* Bandwidth           */
  ULINT BandwidthXUser;  /* Bandwidth per user  */
  char ExpDate[10];                  /* Acl expiration date */
};


/*
 * SS5GLOBAL variables
 * ------------------------------------------------------------------------------------
 *
 */

int S5SocksSocket;

struct sockaddr_in S5SocksSsin;

FILE *S5ConfFile;

FILE *S5PeerFile;

FILE *S5PidFile;                  /* Pid file handle */

char S5PidFileName[MAXPPATHLEN]; /* Path to pid file */
char S5ConfigFile[128];
char S5PeersFile[128];
char S5PasswordFile[128];
char S5LibPath[128];
char S5TracePath[128];
char S5ProfilePath[128];
char S5LoggingFile[128];
char S5RepKey[16];

pthread_mutex_t COMutex;

struct _SS5Peer {
  char IP[16];
} SS5Peer[MAXPEERS];

UINT NPeers;

struct _S5Interface {
  char IP[16];
  char NetMask[16];
} *S5Interface[MAXIF];

UINT NInterF;

struct _SS5SocksOpt {
  char GssPrincipal[64];                 /* Gss principal name */
  unsigned char SupaKey[32];             /* SUPA Secret Key */
  unsigned char ICacheServer[32];        /* Internet cache server for ICP feature */
  int SyslogFa;                          /* Syslog facility */
  int SyslogLe;                          /* Syslog level */
  UINT DnsOrder;                 /* Dns ordering */
  UINT Verbose;                  /* verbose mode */
  UINT Debug;                    /* Debug mode */
  UINT Syslog;                   /* Log to syslog */
  UINT Mute;                     /* No logging */
  UINT Profiling;                /* Set profiling type */
  UINT LdapCriteria;             /* Set Ldap criteria */
  UINT LdapTimeout;              /* Ldap search operation timeout */
  UINT LdapNetbiosDomain;        /* Ldap netbios compatibility */
  UINT AuthCacheAge;             /* Authentication cache age */
  UINT AuthoCacheAge;            /* Authorization cache age */
  UINT StickyAge;                /* Affinity age */
  UINT Sticky;                   /* Affinity feature */
  UINT Authentication;           /* Set authentication type */
  UINT AcceptTimeout;            /* Accept idle timeout */
  UINT IsThreaded;               /* Threaded mode */
  UINT IsBalance;                /* At least a balance line */
  UINT IsUpstream;               /* At least an upstream line */
  UINT IsRoute;                  /* At least a route line */
  UINT IsDump;                   /* At least a dump line */
  UINT IsBandwidth;              /* At least a bandwidth line */
  UINT IsGlobalBandwidth;        /* At least a bandwidth line with a dash as group name */
  UINT IsConsole;                /* Web console enable */
  UINT IsSrvmgr;                 /* Server manager enable */
  UINT Role;                     /* Role of ss5 istance  */
  UINT PreforkProcesses;
  UINT PreforkProcessLife;
  UINT RadInterimTimeout;        /* */
  ULINT PropagateKey;        /* Key for config propagation  */
  ULINT SessionIdleTimeout;  /* Session idle timeout */
  ULINT RadIntUpdInterval;   /* Radius Interim update interval */
  ULINT RadSessionTimeout;    
  ULINT RadSessionIdleTimeout;
} SS5SocksOpt;



/*
 * SOCKS5 module
 * ------------------------------------------------------------------------------------
 *
 */

#define MAXMETHODLIST	997     /* Max auth loadable */
#define MAXROUTELIST	997     /* Max route acl loadable */
#define MAXPROXYLIST	997     /* Max proxy list loadable */
#define MAXBANDLIST	9997    /* Max band list loadable */
#define MAXDNS_RESOLV	30      /* Max hosts resolved */

struct _SS5Socks5Data {
  /* Socks server V5 - Method - */
  char MethodRequest[512];
  char MethodResponse[2];
  int  MethodBytesSent;
  int  MethodBytesReceived;
  /* Socks server V5 - Tcp request - */
  char TcpRequest[256];
  int  TcpRBytesSent;
  int  TcpRBytesReceived;
  /* Socks server V5 - Udp request - */
  char UdpRequest[DATABUF];
  int  UdpRBytesSent;
  int  UdpRBytesReceived;
  /* Socks server V5 - Response - */
  char Response[256];
};

/*
 * SS5: Auth line parameters
 */
struct _S5MethodNode {
  UINT Mask;
  ULINT SrcAddr;      
  ULINT  SrcPort;     
  UINT SrcRangeMin;
  UINT SrcRangeMax;
  UINT Method; 		 
struct _S5MethodNode *next;
};

struct  _S5MethodNode **S5MethodList,
	              **_tmp_S5MethodList,
	              **_old_S5MethodList;

/*
 * SS5: Route line parameters
 */
struct _S5RouteNode {
  UINT Mask;
  ULINT SrcAddr;     /* Source address               */
  ULINT SrcIf;       /* Source interface             */
  char Group[64];                /* Source user group            */
  UINT sd;               /* Source or destination route? */
  struct _S5RouteNode *next;
};

struct _S5RouteNode **S5RouteList,
	            **_tmp_S5RouteList,
	            **_old_S5RouteList;

/*
 * SS5: Upstream socks line parameters
 */
struct _S5ProxyNode {
  UINT Mask;
  UINT Type;
  ULINT DstAddr;    /* Destination ip */
  ULINT DstPort;    /* Destination port */
  UINT DstRangeMax;     /* Destination port */
  UINT DstRangeMin;     /* Destination port */
  ULINT ProxyAddr;  /* Proxy IP */
  UINT ProxyPort;	      /* Proxy port */
  UINT SocksVer;	      /* Socks Ver */
struct _S5ProxyNode *next;
};

struct  _S5ProxyNode **S5ProxyList,
                     **_tmp_S5ProxyList,
                     **_old_S5ProxyList;

/*
 * SS5: Dns response buffer
 */
struct _S5HostList {
  char NextHost[16];
};


/*
 * AUTHENTICATION module
 * ------------------------------------------------------------------------------------
 *
 */

#define MAXAUTHCACHELIST        9997    /* Max authentication cache entries */

/*
 * SS5: Authentication Cache line parameters
 */
struct _S5AuthCacheNode {
  char Usr[64];
  char Pwd[64];
  time_t ttl;
  struct _S5AuthCacheNode *next;
};

struct  _S5AuthCacheNode *S5AuthCacheList[MAXAUTHCACHELIST];

struct _SS5SupaData {
  char NegReq[256];              /* Initial negotiation packet */
  char NegResp[256];            
  char KeyExReq[4096];           /* Key Exchange               */
  char KeyExResp[1024];
  char AuthReq[1024];            /* Authentication request     */
};


/*
 * AUTHORIZATION module
 * ------------------------------------------------------------------------------------
 *
 */

#define MAXLDAPSTORE              20
#define MAXMYSQLSTORE             20
#define MAXACLLIST              9997    /* Max acl loadable */
#define MAXAUTHOCACHELIST       9997    /* Max authorization cache entries */

/*
 * SS5: Permit line parameters
 */
struct _S5AclNode {
  UINT Method;
  UINT Type;
  ULINT SrcAddr;
  char SrcAddrFqdn[64];
  UINT SrcMask;
  ULINT SrcPort;
  UINT SrcRangeMin;
  UINT SrcRangeMax;
  ULINT DstAddr;
  char DstAddrFqdn[64];
  UINT DstMask;
  ULINT DstPort;
  UINT DstRangeMin;
  UINT DstRangeMax;
  char Fixup[16];
  char Group[256];
  ULINT Bandwidth;
  char ExpDate[10];		
  struct _S5AclNode *next;
  };

struct  _S5AclNode **S5AclList,
	           **_tmp_S5AclList,
	           **_old_S5AclList;

/*
 * SS5: Authorization Cache line parameters
 */
struct _S5AuthoCacheNode {
  char Sa[64];
  UINT  Sp;
  char Da[64];
  UINT  Dp;
  char Us[64];
  struct _SS5Facilities Fa;
  time_t ttl;
  UINT Flg;
  struct _S5AuthoCacheNode *next;
};

struct  _S5AuthoCacheNode *S5AuthoCacheList[MAXAUTHOCACHELIST];

/*
 * PROXY  module
 * ------------------------------------------------------------------------------------
 *
 */

#define RECVERR                        -1
#define SENDERR                        -1

struct _SS5ProxyData {
  char *Recv;
  char *Send;
  int BufSize;
  int TcpRBufLen;
  int TcpSBufLen;
  char *UdpRecv;
  char *UdpSend;
  int UdpBufSize;
  int UdpRBufLen;
  int UdpSBufLen;
  UINT Fd;
};


/*
 * BALANCE  module
 * ------------------------------------------------------------------------------------
 *
 */

#define TCB_REQUEST	1
#define STAT_REQUEST	2
#define STICKY_REQUEST	3
#define STICKY_AGE	3600    /* TTL in seconds for sticky feature */
#define MAX_ENTRY_REAL	256     /* Max number of real servers */
#define MAXSTICKYLIST	997

struct _S5ConnectionEntry {
  char Real[16];
  UINT Vid;
  UINT Connection;
};

struct _S5ConnectionTable {
  struct _S5ConnectionEntry **S5ConnectionEntry,
                            **_tmp_S5ConnectionEntry,
                            **_old_S5ConnectionEntry;
} S5ConnectionTable;

UINT NReal,
       _tmp_NReal;


struct _S5StickyNode {
  ULINT srcip;
  ULINT dstip;
  UINT vid;
  time_t ttl;
  struct _S5StickyNode *next;
};

struct _S5StickyNode *S5StickyList[MAXSTICKYLIST];

pthread_mutex_t CTMutex;
pthread_mutex_t CAMutex;


/*
 * STATISTICS  module
 * ------------------------------------------------------------------------------------
 *
 */

#define STAT_REQUEST	2

enum STATCODE {
  AFN=	1,
  AFF=	101,
  AEN=	2,
  AEF=	102,
  APN=	3,
  APF=	103,
  HFN=	4,
  HFF=	104,
  HLN=	5,
  HLF=	105,
  V4CN=	6,
  V4CF=	106,
  V4BN=	7,
  V4BF=	107,
  V5CN=	8,
  V5CF=	108,
  V5BN=	9,
  V5BF=	109,
  V5UN=	10,
  V5UF=	110,
  NONE=	0
};

struct _SS5Statistics {
  ULINT V5Total_Connect,V4Total_Connect;
  ULINT V5Normal_Connect,V4Normal_Connect;
  ULINT V5Failed_Connect,V4Failed_Connect;
  
  ULINT V5Current_Connect,V4Current_Connect;
  
  ULINT V5Total_Bind,V4Total_Bind;
  ULINT V5Normal_Bind,V4Normal_Bind;
  ULINT V5Failed_Bind,V4Failed_Bind;
  
  ULINT V5Current_Bind,V4Current_Bind;
  
  ULINT V5Total_Udp;
  ULINT V5Normal_Udp;
  ULINT V5Failed_Udp;
  
  ULINT V5Current_Udp;
  
  ULINT Total_Auth_File;
  ULINT Total_Auth_EAP;
  ULINT Total_Auth_PAM;
  ULINT Normal_Auth_File;
  ULINT Normal_Auth_EAP;
  ULINT Normal_Auth_PAM;
  ULINT Failed_Auth_File;
  ULINT Failed_Auth_EAP;
  ULINT Failed_Auth_PAM;
  
  ULINT Current_Auth_File;
  ULINT Current_Auth_EAP;
  ULINT Current_Auth_PAM;
  
  ULINT Total_Author_File;
  ULINT Total_Author_Ldap;
  ULINT Normal_Author_File;
  ULINT Normal_Author_Ldap;
  ULINT Failed_Author_File;
  ULINT Failed_Author_Ldap;
  
  ULINT Current_Author_File;
  ULINT Current_Author_Ldap;

} SS5Statistics;

pthread_mutex_t CSMutex;

/*
 * LOGS  module
 * ------------------------------------------------------------------------------------
 *
 */

FILE *S5LogFile;        /* Log file pointer */

/*
 * BANDWIDTH  module
 * ------------------------------------------------------------------------------------
 *
 */

#define MIN_BANDWIDTH           256     /* Bytes per second */

enum ERR_BANDWIDTH {
     ERR_LIMITFOUND= -1
};

struct _S5BandTableNode {
  char Usr[64];
  int  NCon;
  int  LNCon;
  ULINT LBand;
  struct _S5BandTableNode *next;
};

struct _S5GlobalBandwidth {
  ULINT BandW;
  UINT LCon;
} S5GlobalBandwidth;

struct  _S5BandTableNode **S5BandTableList,
                         **_tmp_S5BandTableList,
                         **_old_S5BandTableList;

UINT     NBandwidthList,
            _tmp_NBandwidthList;

pthread_mutex_t BTMutex;


/*
 * DUMP  module
 * ------------------------------------------------------------------------------------
 *
 */

/*
 * SS5: dump line parameters
 */
struct _S5DumpNode {
  UINT Mask;
  ULINT DstAddr;
  ULINT DstPort;
  UINT DstRangeMax;
  UINT DstRangeMin;
  UINT DumpMode;
  struct _S5DumpNode *next;
};

struct  _S5DumpNode **S5DumpList,
                    **_tmp_S5DumpList,
                    **_old_S5DumpList;


/*
 * MODULE FUNCTION POINTERS
 * ------------------------------------------------------------------------------------
 *
 */
struct _module {


  /* Module Authentication VISIBLE functions */
  UINT (*Authentication)(    struct _SS5ClientInfo *ci );
  
  UINT (*SrvAuthentication)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  
  /* HIDDEN */
  UINT (*FreeAuthCache)( struct _S5AuthCacheNode **node );
  
  
  /* Module Socks5 VISIBLE functions */
  UINT (*MethodParsing)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  
  UINT (*RequestParsing)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd,  struct _SS5RequestInfo *ri );
  
  UINT (*UpstreamServing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd);
  
  UINT (*ConnectServing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd);
  
  UINT (*BindServing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd);
  
  UINT (*UdpAssociateServing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd, struct _SS5ProxyData *pd);
  
  UINT (*UdpAssociateResponse)( struct _SS5ClientInfo *ci,struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd, struct _SS5ProxyData *pd); 
  
  UINT (*SrvSocks5)( struct _SS5ClientInfo *ci,struct _SS5Socks5Data *sd );
  
  /* HIDDEN */
  UINT (*AddMethod)(UINT ctx, ULINT sa, ULINT sp, UINT me, UINT mask);
  
  UINT (*FreeMethod)( struct _S5MethodNode **node );
  
  unsigned char (*GetMethod)( ULINT sa, UINT sp);
  
  UINT (*AddRoute)(UINT ctx, ULINT sa, ULINT si, char group[64], UINT mask, UINT sd );
  
  UINT (*FreeRoute)(	struct _S5RouteNode **node );
  
  ULINT (*GetRoute)( ULINT sa, ULINT da, char uname[64] );
  
  UINT (*AddProxy)(UINT ctx, UINT type, ULINT da, ULINT dp, ULINT pa, 
                                  UINT pp, UINT mask, UINT socksver );
  
  UINT (*FreeProxy)(	struct _S5ProxyNode **node );
  
  UINT (*GetProxy)( ULINT da, UINT dp, struct _SS5RequestInfo *ri);
  
  
  /* Module Socks4 VISIBLE functions */
  UINT (*V4RequestParsing)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd, struct _SS5RequestInfo *ri );
  
  UINT (*V4UpstreamServing)(	struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd);
  
  UINT (*V4ConnectServing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd);
  
  UINT (*V4BindServing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd);
  
  /* HIDDEN */
  UINT (*V4AddRoute)( ULINT sa, ULINT si, char *group, UINT mask, UINT sd );
  
  UINT (*V4FreeRoute)( struct _S5RouteNode **node );
  
  ULINT (*V4GetRoute)( ULINT sa, ULINT da, char uname[64]);
  
  
  /* Module Authorization VISIBLE functions */
  UINT (*PreAuthorization)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Facilities *fa);
  
  UINT (*PostAuthorization)(	struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Facilities *fa);
  
  UINT (*SrvAuthorization) ( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );

  UINT (*UpdateAuthoCache) ( char *sa, char *da, UINT dp, char *u, UINT f );
  
  /* HIDDEN */
  UINT (*AddAcl)( UINT ctx, UINT type, ULINT sa, char sfqdn[64], ULINT sp, ULINT da, char dfqdn[64], 
                       ULINT dp, UINT srcmask, UINT dstmask, UINT method, struct _SS5Facilities *fa);
  
  INT (*GetAcl)( ULINT sa, UINT sp, ULINT da, UINT dp, struct _SS5Facilities *fa, UINT *acl);
  
  UINT (*FreeAcl)( struct _S5AclNode **node );
  
  UINT (*FreeAuthoCache)( struct _S5AuthoCacheNode **node );
  
  
  /* Module Balancing  VISIBLE functions */
  UINT (*LoadBalancing)( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri );
  UINT (*Balancing)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  UINT (*SrvBalancing)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  
  /* HIDDEN */
  UINT (*AddConn)( char *real );
  
  UINT (*RemoveConn)( char *real );
  
  UINT (*AddVip)( char *real, UINT vid, UINT index );
  
  UINT (*FreeConnectionTable)( struct _S5ConnectionEntry *ce );
  
  UINT (*FreeAffinity)( struct _S5StickyNode **node );
  
  
  /* Module Proxy  VISIBLE functions */
  UINT (*ReceivingData)( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd,
                                        #ifdef EPOLL_IO
  					struct epoll_event *events );
                                        #else
  					fd_set *s5array );
                                        #endif
  
  UINT (*UdpReceivingData)( int appSocket, struct _SS5ProxyData *pd );
  
  UINT (*SendingData)( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd );
  
  UINT (*UdpSendingData)( int appSocket, struct _SS5RequestInfo *ri, struct _SS5ProxyData *pd );
  
  
  /* Module Dump  VISIBLE functions */
  UINT (*WritingDump)( FILE *df, struct _SS5ProxyData *pd, UINT dm );
  
  UINT (*OpenDump)( FILE **df, struct _SS5ClientInfo *ci );
  
  UINT (*CloseDump)(	FILE *df );
  
  UINT (*GetDump)( ULINT da, UINT dp, struct _SS5DumpInfo *di );
  
  UINT (*AddDump)( UINT ctx, ULINT da, ULINT dp, UINT dm, UINT mask );
  
  UINT (*FreeDump)( struct _S5DumpNode **node );
 
  UINT (*ListDump)( UINT s);
  
  UINT (*SrvDump)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  
  
  /* Module Filter  VISIBLE functions */
  UINT (*Filtering)(	struct _SS5ClientInfo *ci, char *s, struct _SS5ProxyData *pd );
  
  
  /* Module Bandwidth  VISIBLE functions */
  UINT (*Bandwidth)( struct timeval tv, struct _SS5ProxyData *pd, struct _SS5Facilities *fa  );
  
  /* HIDDEN */
  UINT (*GetBandTableC)( char *u );
  
  UINT (*CheckBandTableC)( char *u );
  
  ULINT (*GetBandTableB)( char *u );
  
  UINT (*UpdateBandTable)( char *u, int  n );
  
  UINT (*AddBandTable)( UINT ctx, char *u, int ln, ULINT lb );
  
  UINT (*TransfBandTable)( struct _S5BandTableNode *node );
  
  UINT (*FreeBandTable)( struct _S5BandTableNode **node );
  
  UINT (*SrvBandwidth)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  
  
  /* Module Log  VISIBLE functions */
  UINT (*Logging) ( char *s5logstring );
  
  /* HIDDEN */
  UINT (*Statistics)( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );
  
  UINT (*Summary)( UINT autheerr, UINT authoerr, UINT cmderr );

};


struct _SS5Modules {

  void *mod_socks5_handle;
  struct _module mod_socks5;
  UINT mod_socks5_loaded;

  void *mod_socks4_handle;
  struct _module mod_socks4;
  UINT  mod_socks4_loaded;

  void *mod_authentication_handle;
  struct _module mod_authentication;
  UINT mod_authentication_loaded;

  void *mod_authorization_handle;
  struct _module mod_authorization;
  UINT mod_authorization_loaded;

  void *mod_balancing_handle;
  struct _module mod_balancing;
  UINT mod_balancing_loaded;

  void *mod_proxy_handle;
  struct _module mod_proxy;
  UINT mod_proxy_loaded;

  void *mod_filter_handle;
  struct _module mod_filter;
  UINT mod_filter_loaded;

  void *mod_bandwidth_handle;
  struct _module mod_bandwidth;
  UINT mod_bandwidth_loaded;

  void *mod_logging_handle;
  struct _module mod_logging;
  UINT mod_logging_loaded;

  void *mod_statistics_handle;
  struct _module mod_statistics;
  UINT mod_statistics_loaded;

  void *mod_dump_handle;
  struct _module mod_dump;
  UINT mod_dump_loaded;

} SS5Modules;

#endif
