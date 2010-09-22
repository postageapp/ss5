/* Socks Server 5
 * Copyright (C) 2002 - 2010 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * B
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include"SS5Main.h"
#include"SS5Core.h"
#include"SS5Defs.h"
#include"SS5Server.h"
#include"SS5Radius.h"
#include"SS5Thread.h"
#include"SS5Utils.h"
#include"SS5Debug.h"
#include"SS5Mod_statistics.h"
#include"SS5Mod_balance.h"
#include"SS5Mod_dump.h"
#include"SS5Mod_socks5.h"
#include"SS5Mod_authentication.h"
#include"SS5Mod_authorization.h"


UINT S5Core( int cSocket )
{

  int clientSocket=cSocket;

  struct _SS5ClientInfo     SS5ClientInfo;
  struct _SS5RequestInfo    SS5RequestInfo;
  struct _SS5DumpInfo       SS5DumpInfo;
  struct _SS5Socks5Data     SS5Socks5Data;
  struct _SS5ProxyData      SS5ProxyData;
  struct _SS5Facilities     SS5Facilities;

  FILE *dumpFile;

  pid_t pid;

  time_t startTime;
  time_t stopTime;

  sigset_t signalMask;

  struct timeval btv;

  ULINT tBS = 0;
  ULINT tBR = 0;

  struct sockaddr_in clientSsin;

  char logString[512];


  UINT modErr       =0;
  UINT preforkMode  = ERR;
  UINT autheErr     = NONE;
  UINT authoErr     = NONE;
  UINT cmdErr       = NONE;
  UINT dumpErr      = NONE;

  IFEPOLL( struct epoll_event ev; )
  IFEPOLL( struct epoll_event events[5]; )
  IFEPOLL( int nfds; )
  IFEPOLL( int kdpfd; )

  IFSELECT( int fd; )
  IFSELECT( fd_set arrayFd; )
  IFSELECT( struct timeval tv; )

  /*
   *    Preforked mode, process/thread accept connection after fork/create
   */
  if( !clientSocket ) {
    S5ServerAccept(&clientSsin, &clientSocket);
    preforkMode=OK;
  }

  /*
   *    Block HUP signal
   */
  sigemptyset(&signalMask);
  sigaddset(&signalMask,SIGHUP);
  sigaddset(&signalMask,SIGALRM);
  sigprocmask(SIG_BLOCK,&signalMask,NULL);

  /*
   *    Clear socks buffers
   */
  memset(&SS5ClientInfo,    0,sizeof(struct _SS5ClientInfo));
  memset(&SS5RequestInfo,   0,sizeof(struct _SS5RequestInfo));
  memset(&SS5DumpInfo,      0,sizeof(struct _SS5DumpInfo));
  memset(&SS5Socks5Data,    0,sizeof(struct _SS5Socks5Data));
  memset(&SS5Facilities,    0,sizeof(struct _SS5Facilities));

  SS5ProxyData.Send =    NULL;
  SS5ProxyData.Recv =    NULL;
  SS5ProxyData.UdpSend = NULL;
  SS5ProxyData.UdpRecv = NULL;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   *    Allocate proxy data buffers
   */
  if( (SS5ProxyData.Send = (char *)malloc(DATABUF)) == NULL )
    SS5PCLOSE()
  if( (SS5ProxyData.Recv = (char *)malloc(DATABUF)) == NULL )
    SS5PCLOSE()

  SS5ProxyData.BufSize = DATABUF;

  if( (SS5ProxyData.UdpSend = (char *)malloc(DATABUF)) == NULL )
    SS5PCLOSE()
  if( (SS5ProxyData.UdpRecv = (char *)malloc(DATABUF)) == NULL )
    SS5PCLOSE()

  SS5ProxyData.UdpBufSize = DATABUF;

  /*
   *    Get client info such as socket, source address and source port 
   */
  if( !S5GetClientInfo( &SS5ClientInfo, clientSocket, pid) ) {
    SS5PCLOSE()
  }

  /*
   *    I am a process or a thread?
   */
  if( NOTTHREADED() && (preforkMode == ERR) ) 
    close(S5SocksSocket);

  /*
   *    Get start time
   */
  time(&startTime);

  /*
   *    Module SOCKS5: call --> MethodParsing
   */
  if( (modErr = SS5Modules.mod_socks5.MethodParsing(&SS5ClientInfo, &SS5Socks5Data)) <= ERR ) {
    /*
     *    Module STATISTICS: call --> Statistics
     */
    if( CONSOLE() && MODSTATISTICS() ) {
      modErr = SS5Modules.mod_statistics.Statistics(&SS5ClientInfo,&SS5Socks5Data);
    }
    
    /*
     *    If SS5SRV is enable, manage server commands (see SS5SRV option)
     */
    if( SS5SRV() ) {
      /*
       *    Call core srv
       */
      SrvCore(&SS5ClientInfo,&SS5Socks5Data);

      /*
       *    Module BANDWIDTH: call --> SrvBandwidth
       */
      if( MODBANDWIDTH() ) {
        modErr = SS5Modules.mod_bandwidth.SrvBandwidth(&SS5ClientInfo,&SS5Socks5Data);
      }
      /*
       *    Module SOCKS5: call --> SrvSocks5
       */
      modErr = SS5Modules.mod_socks5.SrvSocks5(&SS5ClientInfo,&SS5Socks5Data);
      /*
       *    Module AUTHENTICATION: call --> SrvAuthentication
       */
      modErr = SS5Modules.mod_authentication.SrvAuthentication(&SS5ClientInfo,&SS5Socks5Data);
      /*
       *    Module AUTHORIZATION: call --> SrvAuthorization
       */
      modErr = SS5Modules.mod_authorization.SrvAuthorization(&SS5ClientInfo,&SS5Socks5Data);
      /*
       *    Module DUMP: call --> SrvDump
       */
      if( MODDUMP() ) {
        modErr = SS5Modules.mod_dump.SrvDump(&SS5ClientInfo,&SS5Socks5Data);
      }
      /*
       *    Module BALANCING: call --> SrvBalancing
       */
      if( MODBALANCING() ) {
        modErr = SS5Modules.mod_balancing.SrvBalancing(&SS5ClientInfo,&SS5Socks5Data);
      }
    }
  
    /*
     *    Module LOGGING: call --> Logging
     *                    Debug statistics data
     */
    if( DEBUG() ) {
      S5DebugStatistics(pid);
    }

    /*
     *    Module BALANCING: call --> Balancing
     */
    if( CONSOLE() && MODBALANCING() && BALANCE() ) {
      modErr = SS5Modules.mod_balancing.Balancing(&SS5ClientInfo,&SS5Socks5Data);
    }

    if( (SS5SocksOpt.Role == SLAVE) && (modErr <= ERR) ) {
      /*
       *    Config receiving for update
       */
      if( (modErr = S5ReceiveConfig( &SS5ClientInfo,&SS5Socks5Data )) == OK ) {
         LOCKMUTEXCO()
         S5LoadConfig(RELOAD_CONFIG);
         UNLOCKMUTEXCO()
      }
    }

    if( modErr <= ERR ) {
      /*
       *    Module LOGGING: call --> Logging
       */
      snprintf(logString,256,"[%u] %s \"\" \"\" %s - - - (-:- -- -:-) (Socks method unknown)",
               pid,SS5ClientInfo.SrcAddr,MSGS5RT[S5REQUEST_ISERROR]);
      LOGUPDATE()
      /*
       *    Module LOGGING: call --> Logging
       *                    Debug method info data
       */
      if( DEBUG() ) {
        S5DebugMethodInfo(pid, SS5ClientInfo);
      }
    }

    SS5PCLOSE()
  }

  if( ISSOCKS5() ) {
    /*
     *    Module AUTHENTICATION: call --> Authentication
     */
    if( SS5Modules.mod_authentication.Authentication( &SS5ClientInfo) <= ERR ) {
      /*
       *    Module LOGGING: call --> Logging
       */
      snprintf(logString,256,"[%u] %s %s \"\" %s - - - (-:- -- -:-) (Authentication failed)",
               pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,MSGS5RT[S5REQUEST_ACLDENY]);
      LOGUPDATE()
      /*
       *    Module LOGGING: call --> Logging
       *                    Debug auth info data
       */
      if( DEBUG() ) {
        S5DebugAuthInfo(pid, SS5ClientInfo);
      } 

      if( MODSTATISTICS() && THREADED() ) {
        /*
         *    Update statistics
         */
        if( AUTHENFILE() ) {
          autheErr=AFF;
        }
        else if( AUTHENEAP() ) {
          autheErr=AEF;
        }
        else if( AUTHENPAM() ) {
          autheErr=APF;
        }
        UPDATESTAT()
      }

      SS5PCLOSE()
    }
  }

  if( THREADED() ) {
    LOCKMUTEXCS()
    if( AUTHENFILE() ) {
      SS5Statistics.Current_Auth_File++;
      autheErr=AFN;
    }
    else if( AUTHENEAP() ) {
      SS5Statistics.Current_Auth_EAP++;
      autheErr=AEN;
    }
    else if( AUTHENPAM() ) {
      SS5Statistics.Current_Auth_PAM++;
      autheErr=APN;
    }
    UNLOCKMUTEXCS()
  }

  if( (ISSOCKS4()) &&  MODSOCKS4() ) {
    /*
     *    Module SOCKS4: call --> RequestParsing
     */
    if( SS5Modules.mod_socks4.V4RequestParsing(&SS5ClientInfo, &SS5Socks5Data, &SS5RequestInfo) <= ERR ) {
      /*
       *    Module LOGGING: call --> Logging
       */
      snprintf(logString,256,"[%u] %s - \"\" %s - - - (-:- -- -:-) (Socks request unknown)",pid,SS5ClientInfo.SrcAddr,
                         MSGS5RT[S4REQUEST_REJECTED]);
      LOGUPDATE()
      /*
       *    Module LOGGING: call --> Logging
       *                    Debug request info data
       */
      if( DEBUG() ) {
        S5DebugRequestInfo(pid, SS5RequestInfo);
      } 

      SS5PCLOSE()
    }
  }
  else if( (ISSOCKS4()) &&  NOTMODSOCKS4() ) {
    /*
     *    Module LOGGING: call --> Logging
     */
    snprintf(logString,256,"[%u] %s \"\" \"\" %s - - - (-:- -- -:-) (Socks request V4 without module loaded)",
                       pid,SS5ClientInfo.SrcAddr,MSGS5RT[S5REQUEST_ISERROR]);
    LOGUPDATE()
    /*
     *    Module LOGGING: call --> Logging
     */
    if( DEBUG() ) {
      S5DebugRequestInfo(pid, SS5RequestInfo);
    } 

    SS5PCLOSE()
  }
  else if( ISSOCKS5() ) {
    /*
     *    Module SOCKS5: call --> RequestParsing
     */
    if( SS5Modules.mod_socks5.RequestParsing(&SS5ClientInfo, &SS5Socks5Data, &SS5RequestInfo) <= ERR ) {
      /*
       *    Module LOGGING: call --> Logging
       */
      snprintf(logString,256,"[%u] %s %s \"\" %s - - - (-:- -- -:-) (No ipv6 support)",
               pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,MSGS5RT[S5REQUEST_ISERROR]);
      LOGUPDATE()
      /*
       *    Module LOGGING: call --> Logging
       */
      if( DEBUG() ) {
        S5DebugRequestInfo(pid, SS5RequestInfo);
      }

      SS5PCLOSE()
    }
  }

  /*
   *    Module BANDWIDTH: call --> Check/Update
   *
   *    Call CheckBandTable to check if is set a limit in the number of connections
   *    for this user. If set update bandwidth table data.
   */
  if( THREADED() && MODBANDWIDTH() ) {
    /*
     *   Check for global bandwidth setting
     */
    if( SS5SocksOpt.IsGlobalBandwidth ) {
      if( NBandwidthList < MAXBANDLIST ) {
        SS5Modules.mod_bandwidth.AddBandTable( ONLINE,SS5ClientInfo.Username, S5GlobalBandwidth.LCon, S5GlobalBandwidth.BandW);
      }
      else {
        snprintf(logString,256 - 1,"[ERRO] Maximum number of bandwidth lines reached: %d.",MAXBANDLIST);
        LOGUPDATE()

        SS5PCLOSE()
      }
    }

    switch( SS5Modules.mod_bandwidth.CheckBandTableC(SS5ClientInfo.Username) ) {
      case OK:
        UPDATEBANDT(1);
        if( SS5SocksOpt.Verbose ) {
          snprintf(logString,256 - 1,"[VERB] [%u] %s Connection limit set for %s.",pid, SS5ClientInfo.SrcAddr, SS5ClientInfo.Username);
          LOGUPDATE()
        }
      break;

      /* LIMIT FOUND FOR THIS USER */
      case ERR_LIMITFOUND:
        /*
         *    Module LOGGING: call --> Logging
         */
        snprintf(logString,256,"[%u] %s %s \"\" %s - - - (-:- -- -:-) (Max number of connections for this user reached)",
                 pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,MSGS5RT[S5REQUEST_ISERROR]);
        LOGUPDATE()

        SS5PCLOSE()
      break;

      /* NO LIMIT FOUND FOR THIS USER */
      case ERR:
      break;
    }
    /*
     *    Module BANDWIDTH: call --> GetBandwidth Look for bandwidth limit per user
     */
    SS5Facilities.BandwidthXUser=SS5Modules.mod_bandwidth.GetBandTableB(SS5ClientInfo.Username);
    if( SS5SocksOpt.Verbose && SS5Facilities.BandwidthXUser ) {
      snprintf(logString,256 - 1,"[VERB] [%u] %s Bandwidth  limit set for %s to: %lu.",pid, SS5ClientInfo.SrcAddr,
                         SS5ClientInfo.Username,SS5Facilities.BandwidthXUser);
      LOGUPDATE()
    }
  }

  /*
   *    Module AUTHORIZATION: call --> PreAuthorization
   *
   *    Call pre_authorization only for CONNECT and BIND operation
   *    and not for UDP_ASSOCIATE.
   */
  if( SS5RequestInfo.Cmd != UDP_ASSOCIATE ) {
    if( SS5Modules.mod_authorization.PreAuthorization( &SS5ClientInfo, &SS5RequestInfo, &SS5Facilities) <= ERR ) {
      /*
       *    Module LOGGING: call --> Logging
       */
      snprintf(logString,256 - 1,"[%u] %s %s \"\" %s - - - (%s:%d -> %s:%d) (Pre authorization failed)",
                         pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,MSGS5RT[S5REQUEST_ACLDENY],
                         SS5ClientInfo.SrcAddr,SS5ClientInfo.SrcPort,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort);
      LOGUPDATE()
      /*
       *    Module LOGGING: call --> Logging
       */
      if( DEBUG() ) {
        S5DebugMethodInfo(pid, SS5ClientInfo);
        S5DebugFacilities(pid, SS5Facilities);
      }

      /*
       *    If RADIUS authentication is enabled, clear sid
       */
      if( AUTHENRADIUS() && SS5ClientInfo.sid )
        SS5ClientInfo.sid=0;
      /*
       *    Update statistics
       */
      if( THREADED() ) {
        if( MODSTATISTICS() ) {

          if( AUTHORFILE() ) {
            authoErr=HFF;
          }
          else if( AUTHORDIRECTORY() ) {
            authoErr=HLF;
          }
          UPDATESTAT()
        }

        /*
         *    Module AUTHORIZATION: call --> UpdateAuthoCache
         */
        if( SS5SocksOpt.AuthoCacheAge ) {
          LOCKMUTEXAC()
          SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);
          UNLOCKMUTEXAC()
        }

        /*
         *    Module BANDWIDTH: call --> Update
         */
        if( MODBANDWIDTH() )
          UPDATEBANDT(-1);
      }

      SS5PCLOSE()
    }
  }
 
  /*
   *    If RADIUS authentication is enabled, does Radius Accounting
   */
  if( AUTHENRADIUS() && SS5ClientInfo.sid )
    S5RadiusAcct(&SS5ClientInfo, 1,  pid);

  if( THREADED() && (SS5RequestInfo.Cmd != UDP_ASSOCIATE) ) {
    LOCKMUTEXCS()
    if( AUTHORFILE() ) {
      SS5Statistics.Current_Author_File++;
      authoErr=HFN;
    }
    else if( AUTHORDIRECTORY() ) {
      SS5Statistics.Current_Author_Ldap++;
      authoErr=HLN;
    }
    UNLOCKMUTEXCS()
  }
  
  switch( SS5RequestInfo.Cmd ) {
    case CONNECT:
      if( (ISSOCKS4()) && MODSOCKS4() ) {
        /* 
         *    Here SOCKS VERSION is 4 
         */
        if( UPSTREAM() )  { 
          if( SS5RequestInfo.ATyp == DOMAIN )
            GETPROXYBYNAME()
          else
            GETPROXYBYADDRESS()
        }
        else
          modErr = ERR;
        /*
         *    Upstreaming connection
         */
        if( modErr ) {
          /*
           *    Module SOCKS4: call --> V4UpstreamServing
           */
          modErr = SS5Modules.mod_socks4.V4UpstreamServing( &SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data );
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V4Current_Connect++;
            UNLOCKMUTEXCS()
            cmdErr=V4CN;
          }
          /*
           *    Module LOGGING: call --> Logging
           */
          if( DEBUG() ) {
            S5DebugUpstreamInfo(pid, SS5RequestInfo);
          }
        }
        /*
         *    Direct connection
         */
        else {
printf("%d %d\n",SS5Modules.mod_balancing_loaded,SS5SocksOpt.IsBalance);
          if( THREADED() && MODBALANCING() && BALANCE()) {
            /*
             *    Module BALANCING: call --> LoadBalancing
             */
puts("CORE: B1");

            modErr = SS5Modules.mod_balancing.LoadBalancing(&SS5ClientInfo, &SS5RequestInfo);
          }
          /*
           *    Module SOCKS4: call --> V4ConnectServing
           */
          modErr = SS5Modules.mod_socks4.V4ConnectServing(&SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data);
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V4Current_Connect++;
            UNLOCKMUTEXCS()
            cmdErr=V4CN;
          }
        }
      }
      else {
        /* 
         *    Here SOCKS VERSION is 5 
         */
        if( UPSTREAM() )  { 
          if( SS5RequestInfo.ATyp == DOMAIN )
            GETPROXYBYNAME()
          else
            GETPROXYBYADDRESS()
        }
        else
          modErr = ERR;
        /*
         *    Upstreaming connection
         */
        if( modErr ) {
          /*
           *    Module SOCKS5: call --> UpstreamServing
           */
          modErr = SS5Modules.mod_socks5.UpstreamServing( &SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data );
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V5Current_Connect++;
            UNLOCKMUTEXCS()
            cmdErr=V5CN;
          }
          /*
           *    Module LOGGING: call --> Logging
           */
          if( DEBUG() ) {
            S5DebugUpstreamInfo(pid, SS5RequestInfo);
          }
        }
        /*
         *    Direct connection
         */
        else {
          if( THREADED() && MODBALANCING() && BALANCE()) {
            /*
             *    Module BALANCING: call --> LoadBalancing
             */
            modErr = SS5Modules.mod_balancing.LoadBalancing(&SS5ClientInfo, &SS5RequestInfo);
          }

          /*
           *    Module SOCKS5: call --> ConnectServing
           */
          modErr = SS5Modules.mod_socks5.ConnectServing(&SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data);
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V5Current_Connect++;
            UNLOCKMUTEXCS()
            cmdErr=V5CN;
          }
        }
      }

      if( modErr <= ERR ) {
        /*
         *    Module LOGGING: call --> Logging
         */
        if( ISSOCKS4() ) {
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                   MSGS5OP[SS5RequestInfo.Cmd - 1], MSGS4RT[(-1 * modErr) - 90],tBR,tBS,
                   SS5ClientInfo.SrcAddr,SS5ClientInfo.SrcPort, SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort);
        }
        else {
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                   MSGS5OP[SS5RequestInfo.Cmd - 1], MSGS5RT[-1 * modErr],tBR,tBS,
                   SS5ClientInfo.SrcAddr,SS5ClientInfo.SrcPort, SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort);
        }
        LOGUPDATE()

        SS5CCLOSE(SS5ClientInfo.appSocket);

        if( THREADED() ) {
          if( MODSTATISTICS() ) {
            /*
             *    Update statistics
             */
            cmdErr +=100;
            UPDATESTAT()
          }

          /*
           *    Module AUTHORIZATION: call --> SrvAuthorization
           */
          if( SS5SocksOpt.AuthoCacheAge ) 
            SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

          /*
           *    Module BANDWIDTH: call --> Update
           */
          if( MODBANDWIDTH() )
            UPDATEBANDT(-1);
        }

        SS5PCLOSE()
      }

      /*
       *    If balancing enabled, add connection to real
       */
      if( THREADED() ) {
        if( MODBALANCING() && BALANCE() ) {
          SS5Modules.mod_balancing.AddConn(SS5RequestInfo.DstAddr);
        }
      }

    break;
    case BIND:
      /*
       *    Module SOCKS5: call --> BindServing
       */
      if( (ISSOCKS4()) && MODSOCKS4() ) {

        if( UPSTREAM() ) {
          if( SS5RequestInfo.ATyp == DOMAIN )
            GETPROXYBYNAME()
          else
            GETPROXYBYADDRESS()
        }
        else
          modErr = ERR;

        if( modErr ) {
          /*
           *    Module SOCKS4: call --> V4UpstreamServing
           */
          modErr = SS5Modules.mod_socks4.V4UpstreamServing(&SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data );
        }
        else {
          modErr = SS5Modules.mod_socks4.V4BindServing(&SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data);
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V4Current_Bind++;
            UNLOCKMUTEXCS()
            cmdErr=V4BN;
          }
        }
      }
      else {
        if( UPSTREAM() ) {
          if( SS5RequestInfo.ATyp == DOMAIN )
            GETPROXYBYNAME()
          else
            GETPROXYBYADDRESS()
        }
        else
          modErr = ERR;

        if( modErr ) {
          /*
           *    Module SOCKS5: call --> UpstreamServing
           */
          modErr = SS5Modules.mod_socks5.UpstreamServing(&SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data );
          /*
           *    Module LOGGING: call --> Logging
           */
          if( DEBUG() ) {
            S5DebugUpstreamInfo(pid, SS5RequestInfo);
          }
        }
        else {
          modErr = SS5Modules.mod_socks5.BindServing(&SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data);
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V5Current_Bind++;
            UNLOCKMUTEXCS()
            cmdErr=V5BN;
          }
        }
      }

      if( modErr <= ERR ) {
        /*
         *    Module LOGGING: call --> Logging
         */
        if( ISSOCKS4() ) {
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                   MSGS5OP[SS5RequestInfo.Cmd-1], MSGS4RT[(-1 * modErr) - 90],tBR,tBS,
                   SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.SrcAddr,SS5ClientInfo.SrcPort);
        }
        else {
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                   MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[-1 * modErr],tBR,tBS,
                   SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.SrcAddr,SS5ClientInfo.SrcPort);
        }
        LOGUPDATE()

        SS5CCLOSE(SS5ClientInfo.appSocket);

        if( THREADED() ) {
          if( MODSTATISTICS() ) {
            /*
             *    Update statistics
             */
            cmdErr +=100;
            UPDATESTAT()
          }

          /*
           *    Module AUTHORIZATION: call --> SrvAuthorization
           */
          if( SS5SocksOpt.AuthoCacheAge ) 
            SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

          /*
           *    Module BANDWIDTH: call --> Update
           */
          if( MODBANDWIDTH() )
            UPDATEBANDT(-1);
        }

        SS5PCLOSE()
      }

    break;
    case UDP_ASSOCIATE:
      SS5ClientInfo.Stream=BEGIN_STREAM;

      do {
        /*
         *    Module SOCKS5: call --> UdpAssociateServing
         */
        if( ((modErr = SS5Modules.mod_socks5.UdpAssociateServing( &SS5ClientInfo, &SS5RequestInfo, &SS5Socks5Data, &SS5ProxyData) ) <= ERR) ) {
          /*
           *    Module LOGGING: call --> Logging
           */
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d)",pid,SS5ClientInfo.udpSrcAddr,SS5ClientInfo.Username,
                   MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[(-1 * modErr)],tBR,tBS,
                   SS5RequestInfo.udpDstAddr,SS5RequestInfo.udpDstPort,SS5ClientInfo.udpSrcAddr,SS5ClientInfo.udpSrcPort);
          LOGUPDATE()
          /*
           *    Module LOGGING: call --> Logging
           */
          if( DEBUG() ) {
            S5DebugUdpRequestInfo(pid, SS5RequestInfo);
          }
  
          SS5CCLOSE(SS5ClientInfo.udpSocket);
          SS5CCLOSE(SS5ClientInfo.appSocket);
          
          if( THREADED() ) {
            if( MODSTATISTICS() ) {
              /*
               *    Update statistics
               */
              cmdErr=V5UF;
              UPDATESTAT()
            }
            /*
             *    Module AUTHORIZATION: call --> SrvAuthorization
             */
            if( SS5SocksOpt.AuthoCacheAge ) 
              SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

            /*
             *    Module BANDWIDTH: call --> Update
             */
            if( MODBANDWIDTH() )
              UPDATEBANDT(-1);
          }

          SS5PCLOSE()
        }

        if( SS5ClientInfo.Stream != END_STREAM ) {
          /*
           *    Update statistics
           */
          if( THREADED() ) {
            LOCKMUTEXCS()
            SS5Statistics.V5Current_Udp++;
            UNLOCKMUTEXCS()
            cmdErr=V5UN;
          }
          /*
           *    Module AUTHORIZATION: call --> PostAutohorization
           * 
           *    Call post_authorization only for UDP_ASSOCIATE operation
           */
          if( SS5Modules.mod_authorization.PostAuthorization(&SS5ClientInfo, &SS5RequestInfo, &SS5Facilities) <= ERR ) {
      
            snprintf(logString,256,"[%u] %s %s \"\" %s - - - (%s:%d -> %s:%d) (Post authorization failed)", 
                                   pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,MSGS5RT[S5REQUEST_ACLDENY],SS5ClientInfo.udpSrcAddr,
                                   SS5ClientInfo.udpSrcPort,SS5RequestInfo.udpDstAddr,SS5RequestInfo.udpDstPort);
            LOGUPDATE()
      
            SS5CCLOSE(SS5ClientInfo.udpSocket);
            SS5CCLOSE(SS5ClientInfo.appSocket);
      
            if( THREADED() ) {
              if( MODSTATISTICS() ) {
                /*
                 *    Update statistics
                 */
                if( AUTHORFILE() ) {
                  authoErr=HFF;
                }
                else if( AUTHORDIRECTORY() ) {
                  authoErr=HLF;
                }
                UPDATESTAT()
              }

              /*
               *    Module AUTHORIZATION: call --> SrvAuthorization
               */
              if( SS5SocksOpt.AuthoCacheAge ) 
                SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

              /*
               *    Module BANDWIDTH: call --> Update
               */
              if( MODBANDWIDTH() )
                UPDATEBANDT(-1);
            }
  
            SS5PCLOSE()
          }
      
          if( THREADED() && (SS5RequestInfo.Cmd == UDP_ASSOCIATE) ) {
            LOCKMUTEXCS()
            if( AUTHORFILE() ) {
              SS5Statistics.Current_Author_File++;
              authoErr=HFN;
            }
            else if( AUTHORDIRECTORY() ) {
              SS5Statistics.Current_Author_Ldap++;
              authoErr=HLN;
            }
            UNLOCKMUTEXCS()
          }

          /*
           *    Module LOGGING: call --> Logging
           */
          snprintf(logString,256,"[%u] %s %s \"%s\" %s 0 0 0 (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                   MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_STARTED],
                   SS5ClientInfo.udpSrcAddr, SS5ClientInfo.udpSrcPort,
                   SS5RequestInfo.udpDstAddr, SS5RequestInfo.udpDstPort);
          LOGUPDATE()
          /*
           *    Module PROXY: call --> UdpSendingData
           */
          if( ((modErr = SS5Modules.mod_proxy.UdpSendingData(SS5ClientInfo.appSocket, &SS5RequestInfo ,&SS5ProxyData)) <= ERR) ) {
      
            snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d) (Udp send error)",pid,
                SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[(-1 * modErr)],tBR,tBS,
                SS5ClientInfo.udpSrcAddr, SS5ClientInfo.udpSrcPort,
                SS5RequestInfo.udpDstAddr, SS5RequestInfo.udpDstPort);
            LOGUPDATE()
      
            SS5CCLOSE(SS5ClientInfo.udpSocket);
            SS5CCLOSE(SS5ClientInfo.appSocket);
      
            if( THREADED() ) {
              if( MODSTATISTICS() ) {
                /*
                 *    Update statistics
                 */
                cmdErr=V5UF;
                UPDATESTAT()
              }

              /*
               *    Module AUTHORIZATION: call --> SrvAuthorization
               */
              if( SS5SocksOpt.AuthoCacheAge ) 
                SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

              /*
               *    Module BANDWIDTH: call --> Update
               */
              if( MODBANDWIDTH() )
                UPDATEBANDT(-1);
            }
  
            SS5PCLOSE()
          }
          tBS +=SS5ProxyData.UdpSBufLen;
      
          /*
           *    Module PROXY: call --> ReceivingData
           */
          if( ((modErr = SS5Modules.mod_proxy.UdpReceivingData(SS5ClientInfo.appSocket, &SS5ProxyData)) <= ERR) ) {
      
            snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d) (Udp receive error)",
                     pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
                     MSGS5OP[SS5RequestInfo.Cmd - 1], MSGS5RT[(-1 * modErr)],tBR,tBS,
                     SS5ClientInfo.udpSrcAddr, SS5ClientInfo.udpSrcPort,
                     SS5RequestInfo.udpDstAddr, SS5RequestInfo.udpDstPort);
            LOGUPDATE()
      
            SS5CCLOSE(SS5ClientInfo.udpSocket);
            SS5CCLOSE(SS5ClientInfo.appSocket);
      
            if( THREADED() ) {
              if( MODSTATISTICS() ) {
                /*
                 *    Update statistics
                 */
                cmdErr=V5UF;
                UPDATESTAT()
              }

              /*
               *    Module AUTHORIZATION: call --> SrvAuthorization
               */
              if( SS5SocksOpt.AuthoCacheAge ) 
                SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

              /*
               *    Module BANDWIDTH: call --> Update
               */
              if( MODBANDWIDTH() )
                UPDATEBANDT(-1);
            }
  
            SS5PCLOSE()
          }
          tBR +=SS5ProxyData.UdpRBufLen;
            
          /*
           *    Module SOCKS5: call --> UdpAssociateResponse
           */
          if( ((modErr = SS5Modules.mod_socks5.UdpAssociateResponse(&SS5ClientInfo, &SS5RequestInfo, 
                                                                    &SS5Socks5Data, 
                                                                    &SS5ProxyData)) <= ERR) ) {
            /*
             *    Module LOGGING: call --> Logging
             */
            snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld - (%s:%d -> %s:%d)",pid,SS5ClientInfo.udpSrcAddr,SS5ClientInfo.Username,
                     MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[(-1 * modErr)],tBR,tBS,
                     SS5ClientInfo.udpSrcAddr,SS5ClientInfo.udpSrcPort,SS5RequestInfo.udpDstAddr,SS5RequestInfo.udpDstPort);
            LOGUPDATE()
      
            SS5CCLOSE(SS5ClientInfo.udpSocket);
            SS5CCLOSE(SS5ClientInfo.appSocket);
      
            if( THREADED() ) {
              if( MODSTATISTICS() ) {
                /*
                 *    Update statistics
                 */
                cmdErr=V5UF;
                UPDATESTAT()
              }

              /*
               *    Module AUTHORIZATION: call --> SrvAuthorization
               */
              if( SS5SocksOpt.AuthoCacheAge ) 
                SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

              /*
               *    Module BANDWIDTH: call --> Update
               */
              if( MODBANDWIDTH() )
                UPDATEBANDT(-1);
            }
  
            SS5PCLOSE()
          }
        }
      } while( SS5ClientInfo.Stream != END_STREAM ); /* End UDP stream */

      /*
       *    Module LOGGING: call --> Logging
       */
      time(&stopTime);

      snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld %.0f (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
          MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_TERMINATED],tBR,tBS,difftime(stopTime,startTime),
          SS5ClientInfo.udpSrcAddr, SS5ClientInfo.udpSrcPort,
          SS5RequestInfo.udpDstAddr, SS5RequestInfo.udpDstPort);

      LOGUPDATE()

      /*   
       *    Close udp socket
       */
      SS5CCLOSE(SS5ClientInfo.udpSocket);
      SS5CCLOSE(SS5ClientInfo.appSocket);

      /*if( THREADED()  && MODSTATISTICS() ) {
        UPDATESTAT()
      }*/

      if( THREADED() ) {
        if( MODSTATISTICS() )  {
          cmdErr +=100;
          UPDATESTAT()
        }

        /*
         *    Module AUTHORIZATION: call --> SrvAuthorization
         */
        if( SS5SocksOpt.AuthoCacheAge ) 
          SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

        /*
         *    Module BANDWIDTH: call --> Update
         */
        if( MODBANDWIDTH() )
          UPDATEBANDT(-1);
      }

      SS5PCLOSE()

    break;
  }


  if( MODDUMP() && DUMP()) {
  /*
   *    Module DUMP: call --> GetDump & OpenDump
   */
    if( (dumpErr=SS5Modules.mod_dump.GetDump(inet_network(SS5RequestInfo.DstAddr),SS5RequestInfo.DstPort,&SS5DumpInfo)) ) {
      if( SS5Modules.mod_dump.OpenDump(&dumpFile,&SS5ClientInfo) <= ERR ) {
        dumpErr=ERR;
        /*
         *    Module LOGGING: call --> Logging
         */
        snprintf(logString,256,"[%u] %s %s \"%s\" %s (%s:%d -> %s:%d) (Error opening dump file)",
                 pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
            MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_ISERROR],
            (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
            (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
            (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
            (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
        LOGUPDATE()
      }
    }
  }

  IFEPOLL( kdpfd=epoll_create(5); )

  IFEPOLL( ev.events = EPOLLIN; )
  IFEPOLL( ev.data.fd = SS5ClientInfo.Socket; )
  IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, SS5ClientInfo.Socket, &ev); )

  IFEPOLL( ev.events = EPOLLIN; )
  IFEPOLL( ev.data.fd = SS5ClientInfo.appSocket; )
  IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, SS5ClientInfo.appSocket, &ev); )

  /*
   *    Module LOGGING: call --> Logging
   */
  snprintf(logString,256,"[%u] %s %s \"%s\" %s 0 0 0 (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
      MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_STARTED],
      (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
      (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
      (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
      (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
  LOGUPDATE()

  if( AUTHENRADIUS() && SS5ClientInfo.sid ) 
    SS5ClientInfo.sessionTime=0;

  /*
   *    Proxy data between client and server through socks server
   */
  while(1) {
    IFSELECT( FD_ZERO(&arrayFd); )
    IFSELECT( FD_SET(SS5ClientInfo.Socket,&arrayFd); )
    IFSELECT( if( SS5ClientInfo.appSocket >0) FD_SET(SS5ClientInfo.appSocket,&arrayFd); )
    /* 
     *    Set socks server session idle timeout
     */
     IFSELECT( if( SS5SocksOpt.RadSessionIdleTimeout ) )
     IFSELECT(   tv.tv_sec =SS5SocksOpt.RadSessionIdleTimeout; )
     IFSELECT( else )
     IFSELECT(   tv.tv_sec =SS5SocksOpt.SessionIdleTimeout; )
     IFSELECT( tv.tv_usec=0; )

     if( MODBANDWIDTH() && (BANDWIDTH() || BANDWIDTHXUSER()) )
       gettimeofday(&btv,NULL);

     if( SS5SocksOpt.SessionIdleTimeout ) {
     IFEPOLL( if( SS5SocksOpt.RadSessionIdleTimeout ) )
     IFEPOLL(   nfds = epoll_wait(kdpfd, events, 5, SS5SocksOpt.RadSessionIdleTimeout*1000); )
     IFSELECT( fd=select(SS5ClientInfo.appSocket+SS5ClientInfo.Socket+1,&arrayFd,NULL,NULL,&tv); )
     IFEPOLL( else )
     IFEPOLL(   nfds = epoll_wait(kdpfd, events, 5, SS5SocksOpt.SessionIdleTimeout*1000); )
     IFSELECT( fd=select(SS5ClientInfo.appSocket+SS5ClientInfo.Socket+1,&arrayFd,NULL,NULL,&tv); )
     }
     else
     IFEPOLL(   nfds = epoll_wait(kdpfd, events, 5, -1); )
     IFSELECT( fd=select(SS5ClientInfo.appSocket+SS5ClientInfo.Socket+1,&arrayFd,NULL,NULL,NULL); )

     IFEPOLL( if( nfds ) { )
     IFSELECT( if( fd ) { )
      /*
       *    Module PROXY: call --> ReceivingData
       */
      IFEPOLL( SS5Modules.mod_proxy.ReceivingData( &SS5ClientInfo, &SS5ProxyData, events); )
      IFSELECT( SS5Modules.mod_proxy.ReceivingData( &SS5ClientInfo, &SS5ProxyData, &arrayFd); )
      /*
       *    Module DUMP: call --> WritingDump
       */
      if( MODDUMP() && DUMP() ) {
        if( dumpErr ) {
          SS5Modules.mod_dump.WritingDump(dumpFile,&SS5ProxyData,SS5DumpInfo.DumpMode);
        }
      }
      /*
       *    Module BANDWIDTH: call --> Bandwidth
       */
      if( MODBANDWIDTH() && BANDWIDTHXUSER() ) {
        SS5Facilities.Bandwidth=SS5Facilities.BandwidthXUser / SS5Modules.mod_bandwidth.GetBandTableC(SS5ClientInfo.Username);
        SS5Modules.mod_bandwidth.Bandwidth( btv, &SS5ProxyData, &SS5Facilities );
        SS5Facilities.Bandwidth=0;
      }
      else if( MODBANDWIDTH() && BANDWIDTH() ) {
          SS5Modules.mod_bandwidth.Bandwidth( btv, &SS5ProxyData, &SS5Facilities );
      }
      /*
       *    Module FILTER: call --> Filtering
       */
      if( MODFILTER() && FILTER() ) {
        if( SS5Modules.mod_filter.Filtering( &SS5ClientInfo, SS5Facilities.Fixup, &SS5ProxyData ) <= ERR ) {
          /*
           *    Get stop time
           */
          time(&stopTime);
          /*
           *    Module LOGGING: call --> Logging
           */
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld %.0f (%s:%d -> %s:%d) (Filter error)",
              pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
              MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_ISERROR],tBR,tBS,difftime(stopTime,startTime),
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
          LOGUPDATE()
  
          /*
           *    If balancing enabled, add connection to real
           */
          if( THREADED() )
            if( MODBALANCING() && BALANCE() ) {
              SS5Modules.mod_balancing.RemoveConn(SS5RequestInfo.DstAddr);
            }

          /*
           *    If dump enabled, close dump file
           */
          if( MODDUMP() && DUMP() ) {
            if( dumpErr ) {
              SS5Modules.mod_dump.CloseDump(dumpFile);
            }
          }
          IFEPOLL( close(kdpfd); )
          SS5CCLOSE(SS5ClientInfo.appSocket); 
  
          if( THREADED() ) {
            if( MODSTATISTICS() )  {
              cmdErr +=100;
              UPDATESTAT()
            }

            /*
             *    Module AUTHORIZATION: call --> SrvAuthorization
             */
            if( SS5SocksOpt.AuthoCacheAge ) 
              SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

            /*
             *    Module BANDWIDTH: call --> Update
             */
            if( MODBANDWIDTH() )
              UPDATEBANDT(-1);
          }

          SS5PCLOSE()
        }
        else
          DISFILTER()
      }

      /*
       *    If radius auth is enabled, and InterimInterval is > 0, update acctsessiontime value. 
       */
      if( AUTHENRADIUS() && SS5ClientInfo.sid ) { 
        time(&stopTime);
        if( (difftime(stopTime,startTime) - SS5ClientInfo.sessionTime) > SS5SocksOpt.RadIntUpdInterval ) {
          SS5ClientInfo.sessionTime=difftime(stopTime,startTime);
          S5RadiusAcct(&SS5ClientInfo, 3,  pid);
        }
       
        if( (difftime(stopTime,startTime) ) > SS5SocksOpt.RadSessionTimeout && SS5SocksOpt.RadSessionTimeout ) {
          /*
           *    Module LOGGING: call --> Logging
           */
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld %.0f (%s:%d -> %s:%d) Session timeout",
              pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
              MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_TERMINATED],tBR,tBS,difftime(stopTime,startTime),
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
          LOGUPDATE()

          /*
           *    If balancing enabled, add connection to real
           */
          if( THREADED() )
            if( MODBALANCING() && BALANCE() ) {
              SS5Modules.mod_balancing.RemoveConn(SS5RequestInfo.DstAddr);
            }
          /*
           *    If dump enabled, close dump file
           */
          if( MODDUMP() && DUMP() ) {
            if( dumpErr ) {
              SS5Modules.mod_dump.CloseDump(dumpFile);
            }
          }

          IFEPOLL( close(kdpfd); )
          SS5CCLOSE(SS5ClientInfo.appSocket);

          if( THREADED() ) {
            if( MODSTATISTICS() )
              UPDATESTAT()

            /*
             *    Module AUTHORIZATION: call --> SrvAuthorization
             */
            if( SS5SocksOpt.AuthoCacheAge ) 
              SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

            /*
             *    Module BANDWIDTH: call --> Update
             */
            if( MODBANDWIDTH() )
              UPDATEBANDT(-1);
          }

          SS5PCLOSE()
        }
      }

      if( !SS5ProxyData.Fd )
        tBS +=SS5ProxyData.TcpRBufLen;
      else
        tBR +=SS5ProxyData.TcpRBufLen;

      if( SS5ProxyData.TcpRBufLen!= RECVERR && SS5ProxyData.TcpRBufLen != ERR) {
        /*
         *    Module PROXY: call --> SendingData
         */
        SS5Modules.mod_proxy.SendingData(&SS5ClientInfo, &SS5ProxyData);

        if( SS5ProxyData.TcpSBufLen == SENDERR  ) { 
          /*
           *    Get stop time
           */
          time(&stopTime);
          /*
           *    Module LOGGING: call --> Logging
           */
          snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld %.0f (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
              MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_TERMINATED],tBR,tBS,difftime(stopTime,startTime),
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
          LOGUPDATE()

          /*
           *    If balancing enabled, add connection to real
           */
          if( THREADED() )
            if( MODBALANCING() && BALANCE() ) {
              SS5Modules.mod_balancing.RemoveConn(SS5RequestInfo.DstAddr);
            }
          /*
           *    If dump enabled, close dump file
           */
          if( MODDUMP() && DUMP() ) {
            if( dumpErr ) {
              SS5Modules.mod_dump.CloseDump(dumpFile);
            }
          }

          IFEPOLL( close(kdpfd); )
          SS5CCLOSE(SS5ClientInfo.appSocket); 

// TO CHECK DIFF PREV STAT
          if( THREADED() ) {
            if( MODSTATISTICS() ) 
              UPDATESTAT()

            /*
             *    Module AUTHORIZATION: call --> SrvAuthorization
             */
            if( SS5SocksOpt.AuthoCacheAge ) 
              SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

            /*
             *    Module BANDWIDTH: call --> Update
             */
            if( MODBANDWIDTH() )
              UPDATEBANDT(-1);
          }

          SS5PCLOSE()
        }
      }
      else {
        /*
         *    Get stop time
         */
        time(&stopTime);

        /*
         *    Module LOGGING: call --> Logging
         */
        snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld %.0f (%s:%d -> %s:%d)",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
              MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_TERMINATED],tBR,tBS,difftime(stopTime,startTime),
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
              (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
        LOGUPDATE()

        /*
         *    If balancing enabled, add connection to real
         */
        if( THREADED() )
          if( MODBALANCING() && BALANCE() ) {
            SS5Modules.mod_balancing.RemoveConn(SS5RequestInfo.DstAddr);
          }

        /*
         *    If dump enabled, close dump file
         */
        if( MODDUMP() && DUMP() ) {
          if( dumpErr ) {
            SS5Modules.mod_dump.CloseDump(dumpFile);
          }
        }

        IFEPOLL( close(kdpfd); )
        SS5CCLOSE(SS5ClientInfo.appSocket);

        if( THREADED() ) {
          if( MODSTATISTICS() ) 
            UPDATESTAT()

            /*
             *    Module AUTHORIZATION: call --> SrvAuthorization
             */
            if( SS5SocksOpt.AuthoCacheAge ) 
              SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

            /*
             *    Module BANDWIDTH: call --> Update
             */
          if( MODBANDWIDTH() )
            UPDATEBANDT(-1);
        } 

        SS5PCLOSE()
      }
    }
    IFEPOLL( else if (nfds == ERR) { )
    IFSELECT( else if (fd == ERR) { )
      /*
       *    Get stop time
       */
      time(&stopTime);

      /*
       *    Module LOGGING: call --> Logging
       */
      snprintf(logString,256,"[%u] %s %s \"%s\" %s %ld %ld %.0f (%s:%d -> %s:%d) Idle timeout",pid,SS5ClientInfo.SrcAddr,SS5ClientInfo.Username,
            MSGS5OP[SS5RequestInfo.Cmd-1], MSGS5RT[S5REQUEST_TERMINATED],tBR,tBS,difftime(stopTime,startTime),
            (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcAddr:SS5RequestInfo.DstAddr,
            (SS5RequestInfo.Cmd==CONNECT)?SS5ClientInfo.SrcPort:SS5RequestInfo.DstPort,
            (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstAddr:SS5ClientInfo.SrcAddr,
            (SS5RequestInfo.Cmd==CONNECT)?SS5RequestInfo.DstPort:SS5ClientInfo.SrcPort);
      LOGUPDATE()


      /*
       *    If balancing enabled, add connection to real
       */
      if( THREADED() )
        if( MODBALANCING() && BALANCE() ) {
          SS5Modules.mod_balancing.RemoveConn(SS5RequestInfo.DstAddr);
        }

      /*
       *    If dump enabled, close dump file
       */
      if( MODDUMP()  && DUMP() ) {
        if( dumpErr ) {
          SS5Modules.mod_dump.CloseDump(dumpFile);
        }
      }

      /*
       *    Session timeout expired
       */
      IFEPOLL( close(kdpfd); )
      SS5CCLOSE(SS5ClientInfo.appSocket);

      if( THREADED() ) {
        if( MODSTATISTICS() ) 
          UPDATESTAT()

        /*
         *    Module AUTHORIZATION: call --> SrvAuthorization
         */
        if( SS5SocksOpt.AuthoCacheAge ) 
          SS5Modules.mod_authorization.UpdateAuthoCache(SS5ClientInfo.SrcAddr,SS5RequestInfo.DstAddr,SS5RequestInfo.DstPort,SS5ClientInfo.Username,-1);

        /*
         *    Module BANDWIDTH: call --> Update
         */
        if( MODBANDWIDTH() )
          UPDATEBANDT(-1);
      }

      SS5PCLOSE()
    }
  }

  IFEPOLL( close(kdpfd); )

  return THREAD_EXIT;
} 


UINT SrvCore( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  if( STREQ(sd->MethodRequest,"GET /list=OPTION HTTP/1.",sizeof("GET /list=OPTION HTTP/1.") - 1) ) {
    ListOption( ci->Socket );
  }
  else if( STREQ(sd->MethodRequest,"GET /list=PEER HTTP/1.",sizeof("GET /list=PEER HTTP/1.") - 1) ) {
    ListPeer( ci->Socket );
  }

  return OK;
}


UINT ListPeer( UINT s)
{
  UINT index;

  char buf[17];

  for(index=0;index<NPeers;index++)
  {
    snprintf(buf,sizeof(buf),"%16s\n",SS5Peer[index].IP);
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }

  return OK;
}


UINT ListOption( UINT s)
{
  char buf[130];

  if( SS5SocksOpt.Role != MASTER ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_ROLE_SLAVE","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.DnsOrder ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_DNSORDER","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.IsConsole ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_CONSOLE","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.IsSrvmgr ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SRV","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.LdapTimeout ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_LDAP_TIMEOUT",SS5SocksOpt.LdapTimeout );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.LdapCriteria == LDAP_BASE ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_LDAP_BASE","LDAP_BASE" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  else if( SS5SocksOpt.LdapCriteria == LDAP_FILTER ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_LDAP_BASE","LDAP_FILTER" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.LdapNetbiosDomain ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_NETBIOS_DOMAIN","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.Authentication == PAM_AUTHENTICATION ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_PAM_AUTH","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.Authentication == RADIUS_AUTHENTICATION ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_RADIUS_AUTH","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.RadIntUpdInterval != 60 ) {
    snprintf(buf,sizeof(buf),"%64s\n%64ld\n","SS5_RADIUS_INTERIM_INT",SS5SocksOpt.RadIntUpdInterval );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.RadInterimTimeout != 9999 ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_RADIUS_INTERIM_TIMEOUT",SS5SocksOpt.RadInterimTimeout );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.AuthCacheAge ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_AUTHCACHEAGE",SS5SocksOpt.AuthCacheAge );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.AuthoCacheAge ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_AUTHOCACHEAGE",SS5SocksOpt.AuthoCacheAge );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.StickyAge ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_STICKYAGE",SS5SocksOpt.StickyAge );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.Sticky ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_STICKY_SESSION","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.Verbose ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_VERBOSE","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.Debug ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_DEBUG","0" );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.SessionIdleTimeout != 1800 ) {
    snprintf(buf,sizeof(buf),"%64s\n%64ld\n","SS5_STIMEOUT",SS5SocksOpt.SessionIdleTimeout );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.AcceptTimeout != 10 ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_ATIMEOUT",SS5SocksOpt.AcceptTimeout );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.SupaKey[0] != '\0' ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SUPAKEY",SS5SocksOpt.SupaKey );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.ICacheServer[0] != '\0' ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_ICACHESERVER",SS5SocksOpt.ICacheServer );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
#ifdef SS5_USE_GSSAPI
  if( SS5SocksOpt.GssPrincipal[0] != '\0' ) {
    snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_GSS_PRINC",SS5SocksOpt.GssPrincipal );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
#endif
  if( SS5SocksOpt.PreforkProcessLife != 256 ) {
    snprintf(buf,sizeof(buf),"%64s\n%64d\n","SS5_PROCESSLIFE",SS5SocksOpt.PreforkProcessLife );
    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.SyslogFa != LOG_LOCAL6 ) {

    if( SS5SocksOpt.SyslogFa == LOG_LOCAL0 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL0" );
    else if( SS5SocksOpt.SyslogFa ==LOG_LOCAL1 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL1" );
    else if( SS5SocksOpt.SyslogFa ==LOG_LOCAL2 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL2" );
    else if( SS5SocksOpt.SyslogFa ==LOG_LOCAL3 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL3" );
    else if( SS5SocksOpt.SyslogFa ==LOG_LOCAL4 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL4" );
    else if( SS5SocksOpt.SyslogFa ==LOG_LOCAL5 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL5" );
    else if( SS5SocksOpt.SyslogFa ==LOG_LOCAL7 )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_FACILITY","LOG_LOCAL7" );

    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }
  if( SS5SocksOpt.SyslogLe != LOG_ERR ) {

    if( SS5SocksOpt.SyslogLe == LOG_EMERG )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_EMERG" );
    else if( SS5SocksOpt.SyslogLe == LOG_ALERT )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_ALERT" );
    else if( SS5SocksOpt.SyslogLe == LOG_CRIT ) 
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_CRIT" );
    else if( SS5SocksOpt.SyslogLe == LOG_WARNING )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_WARNING" );
    else if( SS5SocksOpt.SyslogLe == LOG_NOTICE )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_NOTICE" );
    else if( SS5SocksOpt.SyslogLe == LOG_INFO )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_INFO" );
    else if( SS5SocksOpt.SyslogLe == LOG_DEBUG )
      snprintf(buf,sizeof(buf),"%64s\n%64s\n","SS5_SYSLOG_LEVEL","LOG_DEBUG" );

    if( send(s,buf,sizeof(buf),0) == -1) {
       perror("Send err:");
      return ERR;
    }
  }

  return OK;
}

