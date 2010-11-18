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
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#include"SS5Main.h"
#include"SS5Defs.h"
#include"SS5Utils.h"
#include"SS5Mod_socks5.h"
#include"SS5Mod_authorization.h"
#include"SS5OpenLdap.h"
#include"SS5Mod_log.h"

#ifdef SS5_USE_GSSAPI
#include"SS5GSSApi.h"
#endif

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->MethodParsing=MethodParsing;
  m->RequestParsing=RequestParsing;
  m->UpstreamServing=UpstreamServing;
  m->ConnectServing=ConnectServing;
  m->BindServing=BindServing;
  m->UdpAssociateServing=UdpAssociateServing;
  m->UdpAssociateResponse=UdpAssociateResponse;
  m->AddMethod=AddMethod;
  m->FreeMethod=FreeMethod;
  m->GetMethod=GetMethod;
  m->AddRoute=AddRoute;
  m->FreeRoute=FreeRoute;
  m->GetRoute=GetRoute;
  m->AddProxy=AddProxy;
  m->FreeProxy=FreeProxy;
  m->GetProxy=GetProxy;
  m->SrvSocks5=SrvSocks5;

  return OK;
}

UINT ListRoute( UINT s)
{
  UINT count;

  struct _S5RouteNode *node, *lnode;

  char buf[106];

  for(count = 0;count < MAXROUTELIST; count++) {
    if( (node=S5RouteList[count]) != NULL) {

      lnode=node;
      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%16lu\n%2u\n%16lu\n%64s\n%3u\n",lnode->SrcAddr,lnode->Mask,lnode->SrcIf,lnode->Group,lnode->sd);
          lnode=lnode->next;
        }

        if( send(s,buf,sizeof(buf),0) == -1) {
          perror("Send err:");
          return ERR;
        }
      } while( lnode != NULL );
    }
  }
  return OK;
}

UINT ListMethod( UINT s)
{
  UINT count;

  struct _S5MethodNode *lnode, *node;

  char buf[57];

  for(count = 0;count < MAXMETHODLIST; count++) {
    if( (node=S5MethodList[count]) != NULL) {

      lnode=node;
      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%3u\n%16lu\n%2u\n%16lu\n%5u\n%5u\n",lnode->Method,lnode->SrcAddr,lnode->Mask,lnode->SrcPort,
                   lnode->SrcRangeMin,lnode->SrcRangeMax);
          lnode=lnode->next;
        }

        if( send(s,buf,sizeof(buf),0) == -1) {
          perror("Send err:");
          return ERR;
        }
      } while( lnode != NULL );
    }
  }
  return OK;
}

UINT ListProxy( UINT s)
{
  UINT count;

  struct _S5ProxyNode *node, *lnode;

  char buf[80];

  for(count = 0;count < MAXPROXYLIST; count++) {
    if( (node=S5ProxyList[count]) != NULL) {
      lnode=node;

      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%16lu\n%2u\n%16lu\n%5u\n%5u\n%16lu\n%5u\n%3u\n%3u\n",lnode->DstAddr,lnode->Mask,lnode->DstPort,
               lnode->DstRangeMin,lnode->DstRangeMax,lnode->ProxyAddr,lnode->ProxyPort,lnode->SocksVer,lnode->Type);
          lnode=lnode->next;
        }

        if( send(s,buf,sizeof(buf),0) == -1) {
          perror("Send err:");
          return ERR;
        }
      } while( lnode != NULL );
    }
  }
  return OK;
}

UINT SrvSocks5( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  UINT method,
       srcMask,
       dstMask,
       socksver,
       sdr;
 
  struct in_addr in;

  char sa[64]="\0",           
       sp[16]="\0",          
       da[64]="\0",
       dp[16]="\0",
       pa[16]="\0",
       pp[5]="\0",
       si[16]="\0",
       sv[1]="\0",
       me[1]="\0",
       grp[64]="\0",
       dir[1]="\0";          


  char srvResponse[128];

  if( STREQ(sd->MethodRequest,"GET /list=METHOD HTTP/1.",sizeof("GET /list=METHOD HTTP/1.") - 1) ) {
    ListMethod(ci->Socket);
    return OK;
  } 
  else if( STREQ(sd->MethodRequest,"ADD /method=",sizeof("ADD /method=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"ADD /method=%20s\n%16s\n%1s\n",sa,sp,me);

    switch(me[0]) {
      case '-':    method=NOAUTH;      break;
      case 'u':    method=USRPWD;      break;
      case 'n':    method=FAKEPWD;     break;
      case 's':    method=S_USER_PWD;  break;
#ifdef SS5_USE_GSSAPI
      case 'k':    method=GSSAPI;      break;
#endif
    }

    srcMask=S5GetNetmask(sa);

    if( AddMethod(ONLINE,inet_network(sa),S5GetRange(sp),method,32-srcMask) && ( NMethodList < MAXMETHODLIST) ) {
      strncpy(srvResponse,"OK\0",sizeof("OK\0"));
      NMethodList++;
    }
    else
      strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"DEL /method=",sizeof("DEL /method=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"DEL /method=%20s\n%16s\n%1s\n",sa,sp,me);

    switch(me[0]) {
      case '-':    method=NOAUTH;      break;
      case 'u':    method=USRPWD;      break;
      case 'n':    method=FAKEPWD;     break;
      case 's':    method=S_USER_PWD;  break;
#ifdef SS5_USE_GSSAPI
      case 'k':    method=GSSAPI;      break;
#endif
    }

    srcMask=S5GetNetmask(sa);

    if( DelMethod(inet_network(sa),S5GetRange(sp),method,32-srcMask) && (NMethodList > 0) ) {
      strncpy(srvResponse,"OK\0",sizeof("OK\0"));
      NMethodList--;
    }
    else
      strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"ADD /route=",sizeof("ADD /route=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"ADD /route=%20s\n%16s\n%64s\n%1s\n",sa,si,grp,dir);

     switch(dir[0]) {
        case '-':    sdr=SRC_ROUTE;    break;
        case 's':    sdr=SRC_ROUTE;    break;
        case 'd':    sdr=DST_ROUTE;    break;
        default:     SS5Modules.mod_logging.Logging("[ERRO] SS5SRV: Type unknown in route line.");    return ERR;    break;
    }

    srcMask=S5GetNetmask(sa);
    in.s_addr=inet_addr(si);

    if( AddRoute(ONLINE,inet_network(sa),in.s_addr,grp,32-srcMask,sdr) && ( NRouteList < MAXROUTELIST ) ) {
      strncpy(srvResponse,"OK\0",sizeof("OK\0"));
      NRouteList++;
    }
    else
      strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    SS5SocksOpt.IsUpstream = OK;

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"DEL /route=",sizeof("DEL /route=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"DEL /route=%20s\n%16s\n%64s\n%1s\n",sa,si,grp,dir);

     switch(dir[0]) {
        case '-':    sdr=SRC_ROUTE;    break;
        case 's':    sdr=SRC_ROUTE;    break;
        case 'd':    sdr=DST_ROUTE;    break;
        default:     SS5Modules.mod_logging.Logging("[ERRO] SS5SRV: Type unknown in route line.");    return ERR;    break;
    }

    srcMask=S5GetNetmask(sa);
    in.s_addr=inet_addr(si);

    if( DelRoute(inet_network(sa),in.s_addr,grp,32-srcMask,sdr) && ( NRouteList > 0 ) ) {
      strncpy(srvResponse,"OK\0",sizeof("OK\0"));
      NRouteList--;
    }
    else
      strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    SS5SocksOpt.IsUpstream = OK;

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"ADD /proxy=",sizeof("ADD /proxy=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"ADD /proxy=%20s\n%16s\n%16s\n%5s\n%1s\n",da,dp,pa,pp,sv);

    switch(sv[0]) {
      case '-':    socksver=SOCKS5_VERSION;    break;
      case '5':    socksver=SOCKS5_VERSION;    break;
      case '4':    socksver=SOCKS4_VERSION;    break;
      default:     SS5Modules.mod_logging.Logging("[ERRO] Version unknown in proxy line.");    return ERR;    break;
    }

    dstMask=S5GetNetmask(da);

    in.s_addr=inet_addr(pa);

    if( da[0] >64 ) {
      if( AddProxy(ONLINE,PROXY,S5StrHash(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) && ( NProxyList < MAXPROXYLIST ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList++;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else
      if( AddProxy(ONLINE,PROXY,inet_network(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) && ( NProxyList < MAXPROXYLIST ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList++;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    SS5SocksOpt.IsUpstream = OK;

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"ADD /noproxy=",sizeof("ADD /noproxy=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"ADD /noproxy=%20s\n%16s\n%16s\n%5s\n%1s\n",da,dp,pa,pp,sv);

    switch(sv[0]) {
      case '-':    socksver=SOCKS5_VERSION;    break;
      case '5':    socksver=SOCKS5_VERSION;    break;
      case '4':    socksver=SOCKS4_VERSION;    break;
      default:     SS5Modules.mod_logging.Logging("[ERRO] Version unknown in proxy line.");    return ERR;    break;
    }

    dstMask=S5GetNetmask(da);

    in.s_addr=inet_addr(pa);

    if( da[0] >64 ) {
      if( AddProxy(ONLINE, NOPROXY,S5StrHash(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) && ( NProxyList < MAXPROXYLIST ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList++;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else
      if( AddProxy(ONLINE,NOPROXY,inet_network(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList++;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    SS5SocksOpt.IsUpstream = OK;

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"DEL /proxy=",sizeof("DEL /proxy=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"DEL /proxy=%20s\n%16s\n%16s\n%5s\n%1s\n",da,dp,pa,pp,sv);

    switch(sv[0]) {
      case '-':    socksver=SOCKS5_VERSION;    break;
      case '5':    socksver=SOCKS5_VERSION;    break;
      case '4':    socksver=SOCKS4_VERSION;    break;
      default:     SS5Modules.mod_logging.Logging("[ERRO] Version unknown in proxy line.");    return ERR;    break;
    }

    dstMask=S5GetNetmask(da);

    in.s_addr=inet_addr(pa);

    if( da[0] >64 ) {
      if( DelProxy(PROXY,S5StrHash(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) && ( NProxyList > 0 ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList--;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else
      if( DelProxy(PROXY,inet_network(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) && ( NProxyList > 0 ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList--;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    if( NProxyList == 0 )
      SS5SocksOpt.IsUpstream = ERR;
   
    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"DEL /noproxy=",sizeof("DEL /noproxy=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"DEL /noproxy=%20s\n%16s\n%16s\n%5s\n%1s\n",da,dp,pa,pp,sv);

    switch(sv[0]) {
      case '-':    socksver=SOCKS5_VERSION;    break;
      case '5':    socksver=SOCKS5_VERSION;    break;
      case '4':    socksver=SOCKS4_VERSION;    break;
      default:     SS5Modules.mod_logging.Logging("[ERRO] Version unknown in proxy line.");    return ERR;    break;
    }

    dstMask=S5GetNetmask(da);

    in.s_addr=inet_addr(pa);

    if( da[0] >64 ) {
      if( DelProxy(NOPROXY,S5StrHash(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver) && ( NProxyList > 0 ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList--;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else
      if( DelProxy(NOPROXY,inet_network(da),S5GetRange(dp),in.s_addr,atoi(pp),32-dstMask,socksver)&& ( NProxyList > 0 ) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NProxyList++;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));

    if( NProxyList == 0 )
      SS5SocksOpt.IsUpstream = ERR;
   
    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"GET /list=PROXY HTTP/1.",sizeof("GET /list=PROXY HTTP/1.") - 1) ) {
    ListProxy(ci->Socket);
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"GET /list=ROUTE HTTP/1.",sizeof("GET /list=ROUTE HTTP/1.") - 1) ) {
    ListRoute(ci->Socket);
    return OK;
  }

  return ERR;
}


UINT MethodParsing( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd)
{
  register UINT i;

  char logString[128];

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   * Receive socks V5 method or V4 request
   */
  if( (sd->MethodBytesReceived=recv(ci->Socket,sd->MethodRequest,sizeof(sd->MethodRequest),0)) <= 0 ) {
    ERRNO(pid)
    return ERR;
  }

#ifdef SS5_USE_GSSAPI
  /*
   * Reset GSS encapsulation flag
   */
  ci->GssEnc=GSS_NO_ENC;
#endif

  if( (unsigned char)sd->MethodRequest[0] == SOCKS4_VERSION ) {
    ci->Ver=SOCKS4_VERSION;
    ci->NMeth=0;
    ci->NoAuth=ERR;
    ci->BasicAuth=ERR;
    ci->GssApiAuth=ERR;
    ci->SecureBasicAuth=ERR;
    memcpy(sd->TcpRequest,sd->MethodRequest, sd->MethodBytesReceived);
    sd->TcpRBytesReceived=sd->MethodBytesReceived;

    return OK;
  }
  else if( (unsigned char)sd->MethodRequest[0] == SOCKS5_VERSION ) {
    ci->Ver=SOCKS5_VERSION;
    ci->NMeth=(unsigned char)sd->MethodRequest[1];

    /*    TODO:
     *    Bisogna valorrizzare i campi noauth e basicauth a NO oppure SI
     *    in modo da evidenziare nessuna valorizzazione e quindi nessun
     *    metodo supportato
     */
    for(i=0;i<(ci->NMeth);i++) {
      if( (unsigned char)sd->MethodRequest[2+i] == 0 )
        ci->NoAuth=OK;
      else if ( (unsigned char)sd->MethodRequest[2+i] == 2 )
        ci->BasicAuth=OK;
      else if ( (unsigned char)sd->MethodRequest[2+i] == S_USER_PWD )
        ci->SecureBasicAuth=OK;
#ifdef SS5_USE_GSSAPI
      else if ( (unsigned char)sd->MethodRequest[2+i] == GSSAPI ) 
        ci->GssApiAuth=OK;
#endif
    }
  }
  else {
    return ERR;
  }
  /*
   * Send response V5 to client containing supported methods
   */
  sd->MethodResponse[0]=SOCKS5_VERSION;

  switch( GetMethod(inet_network(ci->SrcAddr), ci->SrcPort) ) {
    case NOAUTH:     sd->MethodResponse[1] = NOAUTH;     ci->Method = (unsigned char)sd->MethodResponse[1];    break;
    case USRPWD:     sd->MethodResponse[1] = USRPWD;     ci->Method = (unsigned char)sd->MethodResponse[1];    break;
    case FAKEPWD:    sd->MethodResponse[1] = USRPWD;     ci->Method = FAKEPWD;                                 break;
    case S_USER_PWD: sd->MethodResponse[1] = S_USER_PWD; ci->Method = (unsigned char)sd->MethodResponse[1];    break;
#ifdef SS5_USE_GSSAPI
    case GSSAPI:     sd->MethodResponse[1] = GSSAPI;     ci->Method = (unsigned char)sd->MethodResponse[1];
                     ci->GssEnc=GSS_ENC_NOINT;                                                                 break;
#endif
    default:
      sd->MethodResponse[1] = (unsigned char)NOMETHOD;
      ci->Method = (unsigned char)sd->MethodResponse[1];
      if( (sd->MethodBytesSent = send(ci->Socket,sd->MethodResponse,sizeof(sd->MethodResponse),SS5_SEND_OPT)) == -1) {
        ERRNO(pid)
        return ERR;
      }
      return ERR;
    break;
  }

  if( (sd->MethodBytesSent = send(ci->Socket,sd->MethodResponse,sizeof(sd->MethodResponse),SS5_SEND_OPT)) == -1) {
    ERRNO(pid);
    return ERR;
  }
  return OK;
}


UINT RequestParsing(struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd, struct _SS5RequestInfo *ri)
{
  UINT i,
               c,
	       len;

  char logString[128];
  
  unsigned char *oubuf;

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  
  memset((char *)sd->TcpRequest, 0, sizeof(sd->TcpRequest));

  if( (sd->TcpRBytesReceived=recv(ci->Socket,sd->TcpRequest,sizeof(sd->TcpRequest),0)) <= 0 ) {
    ERRNO(pid)
    return ERR;
  }

#ifdef SS5_USE_GSSAPI
 /*
  * If GSS method, decode client token
  */
  if( GSSAPI() && GSSINTEGRITY() ) {
    len=sd->TcpRBytesReceived;
    if( S5GSSApiDecode(ci->GssContext, ci->GssEnc, sd->TcpRequest, &oubuf, &len) ) {

      memcpy(sd->TcpRequest,oubuf,len);
      free(oubuf);
    }
    else
      return ERR;
  }
#endif

  ri->Ver=(unsigned char)sd->TcpRequest[0];
  if( (ri->Cmd=(unsigned char)sd->TcpRequest[1]) > 3 )
    return ERR;

  switch( sd->TcpRequest[3] ) {
    case IPV4:
      /*
       * Destination address is dot notation
       */
      ri->ATyp=IPV4;

      ri->DstPort=0;
      ri->DstPort +=(unsigned char)sd->TcpRequest[8];
      ri->DstPort <<=8;
      ri->DstPort +=(unsigned char)sd->TcpRequest[9];

      snprintf(ri->DstAddr,sizeof(ri->DstAddr),"%hu.%hu.%hu.%hu",(unsigned char)sd->TcpRequest[4],
                                                                 (unsigned char)sd->TcpRequest[5],
                                                                 (unsigned char)sd->TcpRequest[6],
                                                                 (unsigned char)sd->TcpRequest[7]);
    break;

    case IPV6: /* Not supported */
      return (-1 * S5REQUEST_ADDNOTSUPPORT);
    break;

    case DOMAIN:
      /*
       * Destination address is FQDN
       */
      len=(unsigned char)sd->TcpRequest[4] + 5;
      ri->DstPort=0;
      ri->DstPort +=(unsigned char)sd->TcpRequest[len];
      ri->DstPort <<=8;
      ri->DstPort +=(unsigned char)sd->TcpRequest[len+1];

      for(c=0,i=5;i<len;i++,c++ )
        ri->DstAddr[c]=(unsigned char)sd->TcpRequest[i];

      ri->DstAddr[c]='\0';
      ri->ATyp=DOMAIN;
    break;
  }

  return OK;
}


UINT UpstreamServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd)
{
  register int i;

  struct sockaddr_in applicationSsin,
                     bindInterfaceSsin;

  char logString[128];

  pid_t pid;

  struct in_addr in;

  int bytes;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  if ( (ci->appSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    ERRNO(pid)
    return( -1 * S5REQUEST_ISERROR );
  }

  /*
   * SS5: set bind interface if configured
   */
  if( ROUTE() ) {
    if( (in.s_addr=(ULINT)GetRoute(inet_network(ci->SrcAddr), inet_network(ri->DstAddr), ci->Username)) ) {

      memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));

      if( (bindInterfaceSsin.sin_addr.s_addr=in.s_addr) ) {
        bindInterfaceSsin.sin_family      = AF_INET;
        bindInterfaceSsin.sin_port        = htons(0);

        if ( bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
          ERRNO(pid)
          return( -1 * S5REQUEST_ISERROR );
        }
      }
    }
  }

  memset((char *)&applicationSsin, 0, sizeof(struct sockaddr_in));
  applicationSsin.sin_family      = AF_INET;
  applicationSsin.sin_port        = htons(ri->upDstPort);
  applicationSsin.sin_addr.s_addr = (ULINT)ri->upDstAddr;

  if( connect(ci->appSocket,(struct sockaddr *)&applicationSsin,sizeof(struct sockaddr_in)) != -1 ) {
    /* 
     * If upstream is requested in V5
     * proxy client method towards upstream socks server
     */
    if( (ri->upSocksVer == SOCKS5_VERSION) && (ci->Ver == SOCKS5_VERSION) ) {
      if( send(ci->appSocket,sd->MethodRequest,sd->MethodBytesReceived,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR );
      }
      if( recv(ci->appSocket,sd->MethodResponse,sizeof(sd->MethodResponse),0) <= 0 ) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR );
      }
    /* Start TEST source code for credentials proxy */
      if (ci->Method == USRPWD || ci->Method == FAKEPWD ) {
        if( send(ci->appSocket,ci->Request,(4+ci->Request[1]+ci->Request[ci->Request[1]+2]),SS5_SEND_OPT) == -1) {
          ERRNO(pid)
          return( -1 * S5REQUEST_ISERROR );
        }
        if( recv(ci->appSocket,ci->Response,sizeof(ci->Response),0) <= 0 ) {
          ERRNO(pid)
          return( -1 * S5REQUEST_ISERROR );
        }
      }
    /* End TEST source code for credentials proxy */
    }

    /* 
     * If upstream is requested in V4, ss5 converts V5 request to V4 request before sending
     * it to upstream socks server
     */
    bytes=sd->TcpRBytesReceived;

    if( (ri->upSocksVer == SOCKS4_VERSION) && (ci->Ver == SOCKS5_VERSION) )
      bytes=V52V4Request(sd, ri, ci);

    /* 
     * Proxy client connect request towards upstream socks server
     */
    if( send(ci->appSocket,sd->TcpRequest,bytes,SS5_SEND_OPT) == -1) {
      ERRNO(pid)
      return( -1 * S5REQUEST_ISERROR );
    }

/*
 * NEW SOURCE 23-04-2007
 */
    if( ri->Cmd == CONNECT ) {
      if( (sd->TcpRBytesReceived=recv(ci->appSocket,sd->Response,sizeof(sd->Response),0)) <= 0 ) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR );
      }

      /* 
       * If upstream is requested in V4, only for CONNECT, ss5 converts V4 response to V5 response before sending
       * it back to client
       */
      bytes=sd->TcpRBytesReceived;

      if( (ri->upSocksVer == SOCKS4_VERSION) && (ci->Ver=SOCKS5_VERSION) )
        bytes=V42V5Response(sd, ri, ci);

      if( send(ci->Socket,sd->Response,bytes,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR );
      }
    }

    if( ri->Cmd == BIND ) {
      /* 
       * Proxy client bind request towards upstream socks server
       */
      if( (sd->TcpRBytesReceived=recv(ci->appSocket,sd->Response,sizeof(sd->Response),0)) <= 0 ) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR );
      }
      /* 
       * Intercept bind ip address: if equal 0.0.0.0, replace it
       */
      if( sd->Response[4] == 0 && sd->Response[5] == 0 && sd->Response[6] == 0 && sd->Response[7] == 0 ) {

        SETADDR_R(sd->Response,ri->upDstAddr,4)
      }

      if( (ri->upSocksVer == SOCKS4_VERSION) && (ci->Ver=SOCKS5_VERSION) ) {
        if( VERBOSE() )
          SS5Modules.mod_logging.Logging("[VERB] Upstream conversion from 5 to 4 not permitted with BIND request.");

        return( -1 * S5REQUEST_ISERROR );
      }

      if( send(ci->Socket,sd->Response,sd->TcpRBytesReceived,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR );
      }
    }
    return OK;
  }
  else {
    return( -1 * S5REQUEST_HOSTUNREACH );
  }

  return OK;
}


UINT ConnectServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd)
{
  register UINT i,index;

  UINT len;

  char logString[128];

  unsigned char *oubuf;

  UINT err=S5REQUEST_SUCCEDED;

  UINT resolvedHostNumber=0;

  struct _S5HostList resolvedHostList[MAXDNS_RESOLV];

  struct sockaddr_in applicationSsin,
                     bindInterfaceSsin;

  struct in_addr in;

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   * SS5: Resolve hostname before connecting
   */ 
  if( ri->ATyp == DOMAIN ) {
    if( S5ResolvHostName(ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR )
      err=S5REQUEST_ISERROR;
  }

  if( err == S5REQUEST_SUCCEDED ) {
    if ( (ci->appSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      ERRNO(pid)
      err=S5REQUEST_ISERROR;
    }
    else { 
      /*
       * SS5: set bind interface if configured
       */ 
      if( ci->framedRoute.sin_addr.s_addr ) {
        memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));
        bindInterfaceSsin.sin_family      = AF_INET;
        bindInterfaceSsin.sin_port        = htons(0);

        bindInterfaceSsin.sin_addr.s_addr=ci->framedRoute.sin_addr.s_addr;
    
        if ( bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
          ERRNO(pid)
          err=S5REQUEST_ISERROR;
        }
      }
      else if( ROUTE() ) {
        /*
         * SS5: set bind interface if configured
         */ 
        if( (in.s_addr=(ULINT)GetRoute(inet_network(ci->SrcAddr), inet_network(ri->DstAddr), ci->Username)) ) {

          memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));
          if( (bindInterfaceSsin.sin_addr.s_addr=in.s_addr) )
          {
            bindInterfaceSsin.sin_family      = AF_INET;
            bindInterfaceSsin.sin_port        = htons(0);
    
            if ( bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
              ERRNO(pid)
              err=S5REQUEST_ISERROR;
            }
          }
        }
      }
      else
      {
        int setFlag = 1;

        memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));
          bindInterfaceSsin.sin_family      = AF_INET;

          socklen_t sl = sizeof(bindInterfaceSsin);

          SS5Modules.mod_logging.Logging("Custom bind routine");

          if (getsockname(ci->Socket, (struct sockaddr*) &bindInterfaceSsin, &sl) != 0)
            bindInterfaceSsin.sin_addr.s_addr = htonl(INADDR_ANY);
          
          bindInterfaceSsin.sin_port = htons(0);

      unsigned char* ip=(char*)&bindInterfaceSsin.sin_addr.s_addr;
      char logString[256];
      snprintf(logString,256 - 1,"[%u] Binding to IP %u.%u.%u.%u (%d)", pid, ip[0], ip[1], ip[2], ip[3], sl);
      LOGUPDATE();

          if (bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
            ERRNO(pid)
            //err=S5REQUEST_ISERROR;
          }
      }
    
      if( err == S5REQUEST_SUCCEDED ) {
        bzero((char *)&applicationSsin, sizeof(struct sockaddr_in));
        applicationSsin.sin_family      = AF_INET;
        applicationSsin.sin_port        = htons(ri->DstPort);
        applicationSsin.sin_addr.s_addr = inet_addr(ri->DstAddr);
    
        if( connect(ci->appSocket,(struct sockaddr *)&applicationSsin,sizeof(struct sockaddr_in)) == -1 ) {
          ERRNO(pid)
          err=S5REQUEST_CONNREFUSED;
          /*
           * Try connecting to other destinations in case of multiple dns answers
           */
          for(index=1;index<resolvedHostNumber;index++) {
            strncpy(ri->DstAddr,resolvedHostList[index].NextHost,sizeof(ri->DstAddr));
            applicationSsin.sin_addr.s_addr = inet_addr(ri->DstAddr);
     
            if( connect(ci->appSocket,(struct sockaddr *)&applicationSsin,sizeof(struct sockaddr_in)) != -1 ) {
              err=S5REQUEST_SUCCEDED;
              break;
            }
          }
        }
      }
    }
  }
    
  /*
   * Prepare and send socks V5 response
   */
  len=10;
  memcpy(sd->Response,sd->TcpRequest,32);

  sd->Response[0]=SOCKS5_VERSION;
  sd->Response[1]=err;
  sd->Response[2]=0;
  sd->Response[3]=IPV4;

  SETADDR(sd->Response,inet_addr(ri->DstAddr),4)
  SETPORT_R(sd->Response,ri->DstPort,8)

#ifdef SS5_USE_GSSAPI
 /*
  * If GSS method, encode response before sending to client
  */
  if( GSSAPI() && GSSINTEGRITY() ) {
    if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, sd->Response, &oubuf, &len) ) {

      memcpy(sd->Response,oubuf,len);
      free(oubuf);
    }
    else
      return ERR;
  }
#endif

  switch( ri->ATyp ) {
    /*
     *    Socks V5 Header is 10 bytes
     */
    case IPV4:
    case DOMAIN:
      if( send(ci->Socket,sd->Response,len,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        err=S5REQUEST_ISERROR;
      }
      break;
    /*
     *    Socks V5 Header is 22 bytes but IPV6 is not supported
     */
    case IPV6:    err=S5REQUEST_ADDNOTSUPPORT;    break;
  }

  if( err != S5REQUEST_SUCCEDED )
     return (-1 * err);
  else
    return OK;
}

UINT BindServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd)
{
char *c=NULL;
*c=0;
  SS5Modules.mod_logging.Logging("Custom BindServing");
  register int i;

  UINT len;

  int cb = 0;

  unsigned char *oubuf;

  char addr[16];

  IFSELECT( UINT fd; );
  IFSELECT( struct timeval tv; )
  IFSELECT( fd_set fdset; )

  UINT resolvedHostNumber=1;

  struct _S5HostList resolvedHostList[MAXDNS_RESOLV];

  struct in_addr in;

  struct sockaddr_in applicationSsin,
                     clientBindSsin;

  char logString[128];

  UINT err=S5REQUEST_SUCCEDED;

  pid_t pid;

  IFEPOLL( struct epoll_event ev; )
  IFEPOLL( struct epoll_event events[5]; )
  IFEPOLL( int nfds; )
  IFEPOLL( int kdpfd; )

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   * SS5: Resolve hostname before binding 
   */ 
  if( ri->ATyp == DOMAIN ) {
    if( S5ResolvHostName(ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR ) {
      err = S5REQUEST_ISERROR;
    }
  }

  if( err == S5REQUEST_SUCCEDED ) {
    /*
     * Create application socket
     */
    if ((ci->appSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      ERRNO(pid)
      err = S5REQUEST_ISERROR;
    }
    else {
      /*
       * Create client socket for bind
       */
      if ((cb = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        ERRNO(pid)
        err = S5REQUEST_ISERROR;
      }
      else {
        memset((char *)&clientBindSsin, 0, sizeof(struct sockaddr_in));
        clientBindSsin.sin_family      = AF_INET;
        clientBindSsin.sin_port        = htons(0);
      
        /*
         * Look for the right interface for binding
         */
        if( S5GetBindIf(ri->DstAddr,addr) == ERR ) {
          /* Match with destination address in socks request */
          
          socklen_t sl = sizeof(clientBindSsin.sin_addr.s_addr);
          if (getsockname(ci->appSocket, (struct sockaddr*) &clientBindSsin.sin_addr.s_addr, &sl) != 0)
            clientBindSsin.sin_addr.s_addr = htonl(INADDR_ANY);

        }
        else
          clientBindSsin.sin_addr.s_addr = inet_addr(addr);
      
        /*
         * SS5: set bind interface if configured
         */ 
        if( ROUTE() ) {
          if( (in.s_addr=(ULINT)GetRoute(inet_network(ci->SrcAddr), inet_network(ri->DstAddr), ci->Username)) )
            clientBindSsin.sin_addr.s_addr = in.s_addr;
        } 
        if (bind(cb, (struct sockaddr *)&clientBindSsin, sizeof(struct sockaddr_in)) == -1) {
          ERRNO(pid)
          err = S5REQUEST_ISERROR;
        }
        else {
          /*
           * Get clientbind info
           */
          len=sizeof(struct sockaddr);
          getsockname(cb,(struct sockaddr *)&clientBindSsin,&len);
           in.s_addr= clientBindSsin.sin_addr.s_addr;
          /*
           * SS5: listen for a queue length equal to one
           */ 
          if (listen(cb, 1) == -1) {
            ERRNO(pid)
            err = S5REQUEST_ISERROR;
          }
        }
      }
    }
  }

  /*
   * Send socks response
   */
  len=10;
  memcpy(sd->Response,sd->TcpRequest,32);

  sd->Response[0]=SOCKS5_VERSION;
  sd->Response[1]=err;
  sd->Response[2]=0;

  SETADDR(sd->Response,clientBindSsin.sin_addr.s_addr,4)
  SETPORT_R(sd->Response,clientBindSsin.sin_port,8)

  switch( ri->ATyp ) {
    /* Socks V5 Header is 10 bytes */
    case IPV4:
    case DOMAIN:
      sd->Response[3]=IPV4;
    break;
    /*
     *    Socks V5 Header is 22 bytes but IPV6 is not supported
     */
    case IPV6:    
      return (-1 * S5REQUEST_ADDNOTSUPPORT);
    break;
  }

#ifdef SS5_USE_GSSAPI
 /*
  * If GSS method, encode response before sending to client
  */
  if( GSSAPI() && GSSINTEGRITY() ) {
    if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, sd->Response, &oubuf, &len) ) {

      memcpy(sd->Response,oubuf,len);
      free(oubuf);
    }
    else
      return ERR;
  }
#endif

  /*
   * Send socks response
   */
  if( send(ci->Socket,sd->Response,len,SS5_SEND_OPT) == -1) {
    ERRNO(pid)
    return(-1 * S5REQUEST_ISERROR);
  }

  if( err == S5REQUEST_SUCCEDED ) {
    /* 
     * Wait for BIND_TIMEOUT before closing listen port
     */
    bzero((char *)&applicationSsin, sizeof(struct sockaddr_in));
    len = sizeof (struct sockaddr_in);
  
    IFSELECT( FD_ZERO(&fdset); )
    IFSELECT( FD_SET(cb,&fdset); )

    IFSELECT( tv.tv_sec=BIND_TIMEOUT; )
    IFSELECT( tv.tv_usec=0; )

    IFEPOLL( kdpfd=epoll_create(5); )
    IFEPOLL( ev.events = EPOLLIN; )
    IFEPOLL( ev.data.fd = cb; )
    IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, cb, &ev); )

    IFSELECT( if( (fd=select(cb+1,&fdset,NULL,NULL,&tv)) ) { )
    IFEPOLL(  if( (nfds = epoll_wait(kdpfd, events, 5, BIND_TIMEOUT*1000)) ) { )
    IFSELECT( if( FD_ISSET(cb,&fdset) ) { )
    IFEPOLL(  if( events[0].data.fd == cb ) { )
        if ((ci->appSocket = accept(cb, (struct sockaddr *)&applicationSsin, &len)) == -1) {
          ERRNO(pid)
          
          IFEPOLL( close(kdpfd); )
          close(cb);
          return (-1 * S5REQUEST_TTLEXPIRED);
        }
      }
    }
    else {
      /*
       * Timeout expired accepting connection from remote application
       */
      IFEPOLL( close(kdpfd); )
      close(cb);
      return (-1 * S5REQUEST_TTLEXPIRED);
    }

    IFEPOLL( close(kdpfd); )

    /*
     * Socks response packet
     */
    sd->Response[1]=S5REQUEST_SUCCEDED;

    switch( ri->ATyp ) {
      /*
       *    Socks V5 Header is 10 bytes
       */
      case IPV4:
      case DOMAIN:
        if( send(ci->Socket,sd->Response,10,SS5_SEND_OPT) == -1) {
          ERRNO(pid)
          return(-1 * S5REQUEST_ISERROR);
        }
      break;
  
      /*
       *    Socks V5 Header is 22 bytes but IPV6 is not supported
       */
      case IPV6:    return (-1 * S5REQUEST_ADDNOTSUPPORT);    break;
    }
  }

  if( err != S5REQUEST_SUCCEDED )
     return (-1 * err);
  else
    return OK;

}


UINT UdpAssociateServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd, struct _SS5ProxyData *pd)
{
  register UINT i;

  UINT len;

  IFSELECT( UINT fd; )

  unsigned short ipA,
                 ipB,
                 ipC,
                 ipD;

  unsigned char *oubuf;

  char addr[16];
 
  unsigned char gssHeader[4];

  char logString[256];

  pid_t pid;

  IFSELECT( fd_set fdset; )
  IFSELECT( struct timeval tv; )

  UINT resolvedHostNumber=1;

  struct _S5HostList resolvedHostList[MAXDNS_RESOLV];

  struct in_addr in;

  struct sockaddr_in serverbind_ssin,
                     clientBindSsin;

  IFEPOLL( struct epoll_event ev; )
  IFEPOLL( struct epoll_event events[5]; )
  IFEPOLL( int nfds; )
  IFEPOLL( int kdpfd; )

  UINT err=S5REQUEST_SUCCEDED;

  if( ci->Stream == BEGIN_STREAM ) {
    /*
     *    Get child/thread pid
     */
    if( NOTTHREADED() )
      pid=getpid();
    else
      pid=(UINT)pthread_self();
  
    /*
     * SS5: Resolve hostname before binding
     */
    if( ri->ATyp == DOMAIN ) {
      if( S5ResolvHostName(ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR ) {
        err=S5REQUEST_ISERROR;
      }
    }
  
    if( err == S5REQUEST_SUCCEDED ) {
      /*
       * Create server socket vs client
       */
      if ((ci->udpSocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        ERRNO(pid)
        err=S5REQUEST_ISERROR;
      }
      else {
        memset((char *)&serverbind_ssin, 0, sizeof(struct sockaddr_in));
        serverbind_ssin.sin_family      = AF_INET;
        serverbind_ssin.sin_port        = htons(0);
      
        /*
         * Look for the right interface to bind before
         * receiving socks request from client (UDP)
         */
        if( S5GetBindIf(ri->DstAddr,addr) ) {                
          /* Match with destination address in socks request */
          serverbind_ssin.sin_addr.s_addr = inet_addr(addr);	
        }
        else if( S5GetBindIf(ci->SrcAddr,addr) ) {
          /* Match with client source address*/
          serverbind_ssin.sin_addr.s_addr = inet_addr(addr);
        }
        else {
          /* Bind ANY (if option set) */
          len = sizeof (struct sockaddr_in);
          getsockname(ci->Socket,(struct sockaddr *)&serverbind_ssin,&len);
        }
      
        /*
         * SS5: bind socket to manage request vs client
         */
        if( bind(ci->udpSocket,(struct sockaddr *)&serverbind_ssin,sizeof(struct sockaddr_in)) ) {
          ERRNO(pid)
          err=S5REQUEST_ISERROR;
        }
        else {
          /*
           * Get information about ip and port after bind operation
           * to send to client
           */
          len = sizeof (struct sockaddr_in);
          getsockname(ci->udpSocket,(struct sockaddr *)&serverbind_ssin,&len);
        }
      }
    }
  
    /*
     * SS5: create response to send to client
     */
    len=10;
    memset(sd->Response,0,sizeof(sd->Response));
  
    sd->Response[0]=SOCKS5_VERSION;
    sd->Response[1]=err;
    sd->Response[2]=0;
    
    SETADDR(sd->Response,serverbind_ssin.sin_addr.s_addr,4)
    SETPORT(sd->Response,serverbind_ssin.sin_port,8)
  
    switch( ri->ATyp ) {
      /* Socks V5 Header 10 Bytes */
      case IPV4:
        sd->Response[3]=IPV4;
      break;
      /* Socks V5 Header 10 Bytes */
      case DOMAIN:
        sd->Response[3]=DOMAIN;
      break;
      /*
       *    Socks V5 Header is 22 Bytesi but is not supported
       */
      case IPV6:    
        return (-1 * S5REQUEST_ADDNOTSUPPORT);    
      break;
    }
  
#ifdef SS5_USE_GSSAPI
   /*
    * If GSS method, encode response before sending to client
    */
    if( GSSAPI() && GSSINTEGRITY() ) {
      if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, sd->Response, &oubuf, &len) ) {
        memcpy(sd->Response,oubuf,len);
        free(oubuf);
      }
      else
        return ERR;
    }
#endif
  
   /*
    *    Socks V5 Header is 10 bytes
    */
    if( send(ci->Socket,sd->Response,len,SS5_SEND_OPT) == -1) {
      ERRNO(pid)
      return( -1 * S5REQUEST_ISERROR);
    }

  } /* End UDP stream */

  if( err == S5REQUEST_SUCCEDED ) {
    /*
     * Wait for receiving socks V5 request from client
     * until UDP_TIMEOUT value
     */
    IFSELECT( FD_ZERO(&fdset); )
    IFSELECT( FD_SET(ci->udpSocket,&fdset); )
    IFSELECT( FD_SET(ci->Socket,&fdset); )

    IFSELECT( tv.tv_sec=UDP_TIMEOUT; )
    IFSELECT( tv.tv_usec=0; )

    IFEPOLL( kdpfd=epoll_create(5); )
    IFEPOLL( ev.events = EPOLLIN; )
    IFEPOLL( ev.data.fd = ci->udpSocket; )
    IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, ci->udpSocket, &ev); )
    IFEPOLL( ev.events = EPOLLIN; )
    IFEPOLL( ev.data.fd = ci->Socket; )
    IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, ci->Socket, &ev); )
 
    len=sizeof(struct sockaddr_in);
    memset(sd->UdpRequest,0,sizeof(sd->UdpRequest));
  

    IFSELECT( if( (fd=select(ci->Socket+ci->udpSocket+1,&fdset,NULL,NULL,&tv)) ) { )
    IFEPOLL( if( (nfds = epoll_wait(kdpfd, events, 5, UDP_TIMEOUT*1000)) ) { )
      IFSELECT( if( FD_ISSET(ci->udpSocket,&fdset) ) { )
      IFEPOLL(  if( events[0].data.fd == ci->udpSocket ) { )
#ifdef SS5_USE_GSSAPI
       /*
        * If GSS method, decode proxy data received from client
        */
        if( GSSAPI() && GSSINTEGRITY() ) {

         /*
          * Read GSS Header from the beginning of the receive queue
          */
          sd->UdpRBytesReceived=recvfrom(ci->udpSocket,gssHeader,sizeof(gssHeader),MSG_PEEK,(struct sockaddr *)&clientBindSsin,(socklen_t *)&len);
          GET_GSSHEADER_LEN(gssHeader,len,GSS_OFFSET_HLEN)
          len +=4;

         /*
          * If token is bigger then default buffer size, realloc proxy data buffer
          */
          if( (len > pd->UdpBufSize) && (len < MAX_GSSTOKEN_SIZE) ) {
            pd->UdpRecv=realloc(pd->UdpRecv,(len));
            pd->UdpSend=realloc(pd->UdpSend,(len));
            pd->UdpBufSize=len;
          }

          memset(sd->UdpRequest,0,sizeof(sd->UdpRequest));
          sd->UdpRBytesReceived=recvfrom(ci->udpSocket,sd->UdpRequest,sizeof(sd->UdpRequest),0,(struct sockaddr *)&clientBindSsin,(socklen_t *)&len);

          if( (len=sd->UdpRBytesReceived) ) {
            if( S5GSSApiDecode(ci->GssContext, ci->GssEnc, sd->UdpRequest, &oubuf, &len) ) {

              memcpy(sd->UdpRequest,oubuf,len);
              free(oubuf);
              sd->UdpRBytesReceived=len;
            }
            else
              return ERR;
          }
        }
        else {
#endif
          if( (sd->UdpRBytesReceived=recvfrom(ci->udpSocket,sd->UdpRequest,sizeof(sd->UdpRequest),0,(struct sockaddr *)&clientBindSsin,
              (socklen_t *)&len)) == -1 ) {
            ERRNO(pid)
            IFEPOLL( close(kdpfd); )
            return( -1 * S5REQUEST_ISERROR);
          }
#ifdef SS5_USE_GSSAPI
        }
#endif
      }
      IFSELECT( else if( FD_ISSET(ci->Socket,&fdset) ) { )
      IFEPOLL(  else if( events[0].data.fd == ci->Socket ) { )
        ci->Stream = END_STREAM;
        IFEPOLL( close(kdpfd); )
        return OK;
      }
    }
    else {
      /* UDP timeout expired */
      IFEPOLL( close(kdpfd); )
      return( -1 * S5REQUEST_TTLEXPIRED);
    }
  
    IFEPOLL( close(kdpfd); )

    /*
     * Set udp request info
     */
    ri->udpATyp=(unsigned char)sd->UdpRequest[3]; 
    ri->udpFrag=(unsigned char)sd->UdpRequest[2];
  
    /*
     * Check for fragmentation bit set
     */
    if( ri->udpFrag ) {
      return( -1 * S5REQUEST_ISERROR);
    } 
    /*
     * Get remote peer address and port 
     * to set udp client info
     */
  
    in.s_addr=clientBindSsin.sin_addr.s_addr;
    strncpy(addr,(char *)inet_ntoa(in),sizeof(addr));
  
    sscanf((const char *)addr,"%hu.%hu.%hu.%hu",&ipA,&ipB,&ipC,&ipD);
  
    strncpy(ci->udpSrcAddr,addr,sizeof(ci->udpSrcAddr));
    ci->udpSrcPort=ntohs(clientBindSsin.sin_port);
  
    /*
     * Set udp request info
     */ 
    switch( ri->udpATyp ) {
      case IPV4:
        ri->udpDstPort=0;
        ri->udpDstPort +=(unsigned char)sd->UdpRequest[8];
        ri->udpDstPort <<=8;
        ri->udpDstPort +=(unsigned char)sd->UdpRequest[9];
  
        snprintf(ri->udpDstAddr,sizeof(ri->DstAddr),"%hu.%hu.%hu.%hu",(unsigned char)sd->UdpRequest[4],
                                                                    (unsigned char)sd->UdpRequest[5],
                                                                    (unsigned char)sd->UdpRequest[6],
                                                                    (unsigned char)sd->UdpRequest[7]);
        /*
         * Move data after socks header to proxy buffer
         */
        for(i=0;i<((UINT)sd->UdpRBytesReceived-10);i++)
          pd->UdpSend[i]=sd->UdpRequest[i+10];
  
        pd->UdpSBufLen=sd->UdpRBytesReceived-10;
      break;
  
      case IPV6: 
        /* IPV6 is not supported */
        return (-1 * S5REQUEST_ADDNOTSUPPORT);
      break;
  
      case DOMAIN:
        len=(unsigned char)sd->UdpRequest[4] + 5;
  
        ri->udpDstPort=0;
        ri->udpDstPort +=(unsigned char)sd->UdpRequest[len];
        ri->udpDstPort <<=8;
        ri->udpDstPort +=(unsigned char)sd->UdpRequest[len+1];
  
        for(i=0,i=5;i<len;i++,i++ )
          ri->udpDstAddr[i]=sd->UdpRequest[i+2];
        ri->udpDstAddr[i]='\0';
  
        /*
         * Move data after socks header to proxy buffer
         */
        len=7+sd->UdpRequest[4];
        for(i=0;i<(sd->UdpRBytesReceived-len);i++)
          pd->UdpSend[i]=sd->UdpRequest[i+len];

        pd->UdpSBufLen=sd->UdpRBytesReceived-len;
      break;
    }
  
    /*
     * Verify client source address and port
     * are the same as specified in socks request
     */
    if( getenv("SS5_SOCKS_UDP_NOSTRICT") == NULL ) {
      if( S5VerifyBind(ci,ri) == ERR ) {
        if( VERBOSE() )
        {
          snprintf(logString,128,"[%u] [VERB] UDP packet received doesn't match any UDP_ASSOCIATE request.",pid);
          LOGUPDATE()
        }
        return( -1 * S5REQUEST_ACLDENY);
      }
    }
    else {
      snprintf(logString,196,"[%u] [DEBU] Found SS5_SOCKS_UDP_NOSTRICT environment variable."
                             " Security check (as described in RFC 1928) in UDP_ASSOCIATE request DISABLED.",pid);
      LOGUPDATE()
    }
    /*
     * SS5: Resolve hostname of udp destination address
     */ 
    if( ri->ATyp == DOMAIN )
      if( S5ResolvHostName((struct _SS5RequestInfo *)ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR )
        return( -1 * S5REQUEST_ISERROR);
  
    if( ci->Stream == BEGIN_STREAM ) {
      /*
       * SS5: create socket for application
       */ 
      if ((ci->appSocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        ERRNO(pid)
        return( -1 * S5REQUEST_ISERROR);
      }
    } /* End UDP stream */
  } 

  ci->Stream=CONTINUE_STREAM;

  if( err != S5REQUEST_SUCCEDED )
     return (-1 * err);
  else
    return OK;
}


UINT UdpAssociateResponse(struct _SS5ClientInfo *ci,struct _SS5RequestInfo *ri,  struct _SS5Socks5Data *sd, struct _SS5ProxyData *pd)
{
  register int i;

  UINT len, datalen;

  pid_t pid;

  char logString[128];

  unsigned char *oubuf;

  struct sockaddr_in clientBindSsin;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  memset((char *)&clientBindSsin, 0, sizeof(struct sockaddr_in));
  clientBindSsin.sin_family      = AF_INET;
  clientBindSsin.sin_port        = htons(ci->udpSrcPort);
  clientBindSsin.sin_addr.s_addr = inet_addr(ci->udpSrcAddr);

  memset(sd->UdpRequest,0,sizeof(sd->UdpRequest));

  datalen=pd->UdpRBufLen+10; 

  switch( ri->udpATyp ) {
    case IPV4:
    case DOMAIN:
      sd->UdpRequest[0]=0;
      sd->UdpRequest[1]=0;
      sd->UdpRequest[2]=ri->udpFrag;
      sd->UdpRequest[3]=ri->udpATyp;

      SETADDR(sd->UdpRequest,inet_addr(ri->udpDstAddr),4)
      SETPORT_R(sd->UdpRequest,ri->udpDstPort,8)

    break;
    /*
     *    Socks V5 Header is 22 bytes but IPV6 is not supported
     */
    case IPV6:    return (-1 * S5REQUEST_ADDNOTSUPPORT);    break;
  }

  /*
   * Send response to client
   */
  for(i=0;i<(pd->UdpRBufLen);i++)
    sd->UdpRequest[i+10]=pd->UdpRecv[i];

#ifdef SS5_USE_GSSAPI
 /*
  * If GSS method, encode response before sending to client
  */
  if( GSSAPI() && GSSINTEGRITY() ) {
    if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, sd->UdpRequest, &oubuf, &datalen) ) {
      memcpy(sd->Response,oubuf,datalen);
      free(oubuf);
    }
    else
      return ERR;
  }
#endif

  /*
   * Relay application response to client
   */
  len=sizeof(struct sockaddr_in);

  if( (sd->UdpRBytesSent=sendto(ci->udpSocket,sd->UdpRequest,datalen,0,(struct sockaddr *)&clientBindSsin,(socklen_t)len)) == -1 ) {
    ERRNO(pid)
    return (-1 * S5REQUEST_ISERROR);
  }

  return OK;
}


UINT S5GetBindIf( char *applicationIp, char *clientBind )
{
  int index;

  bzero(clientBind,16);

  if( (index=S5IfMatch(applicationIp)) != -1 ) {
    strncpy(clientBind,S5Interface[index]->IP,sizeof(S5Interface[index]->IP) - 1);
    return OK;
  }
  return ERR;
}


UINT S5ResolvHostName( struct _SS5RequestInfo *ri, struct _S5HostList *resolvedHostList, UINT *resolvedHostNumber)
{
  register UINT index,count;

  struct addrinfo *result;
  struct addrinfo *res;
  int error;

  char hostname[32], logString[128];

  pid_t pid;
  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

   /* resolve the domain name into a list of addresses */
  if( (error = getaddrinfo(ri->DstAddr, NULL, NULL, &result)) != 0 ) {

    return ERR;
  }
  /*
   * In case of multiple answers, save all
   */
  *resolvedHostNumber=0;
  for (index=0,res = result; res != NULL && index < MAXDNS_RESOLV; res = res->ai_next,index++) {
    if( (error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, 32, NULL, 0, NI_NUMERICHOST)) == 0 ) {
      if (*hostname && res->ai_family == PF_INET) {

          strncpy(resolvedHostList[*resolvedHostNumber].NextHost,hostname,sizeof(resolvedHostList[*resolvedHostNumber].NextHost));
          *resolvedHostNumber=*resolvedHostNumber + 1;
      }
    }
  }
  if( result )
    freeaddrinfo(result);

  /* 
   * If request, order dns answers
   */
  if( SS5SocksOpt.DnsOrder ) {
    S5OrderIP(resolvedHostList, resolvedHostNumber);

    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [VERB] Ordering multiple records dns.",pid);
      LOGUPDATE()

      for(count=0;count<*resolvedHostNumber; count++) {
        snprintf(logString,128,"[%u] [VERB] Resolved %s to %s.",pid,ri->DstAddr,resolvedHostList[count].NextHost);
        LOGUPDATE()
      }
    }
  }

  strncpy(ri->DstAddr,resolvedHostList[0].NextHost,sizeof(ri->DstAddr));

  return OK;
}

UINT S5OrderIP( struct _S5HostList *resolvedHostList, UINT *resolvedHostNumber )
{
  register UINT index;

  UINT swap;
  
  char ip_tmp[16];

  do {
    swap=0;
    for(index=0;index<(*resolvedHostNumber)-1;index++)
      if( S5CompIP(resolvedHostList[index].NextHost,resolvedHostList[index+1].NextHost) ) {
        strncpy(ip_tmp,resolvedHostList[index+1].NextHost,sizeof(resolvedHostList[index+1].NextHost) - 1);
        strncpy(resolvedHostList[index+1].NextHost,resolvedHostList[index].NextHost,sizeof(resolvedHostList[index].NextHost) - 1);
	strncpy(resolvedHostList[index].NextHost,ip_tmp,sizeof(ip_tmp) - 1);
	swap=1;
      }
  } while(swap);

  return OK;
}

UINT S5CompIP(char src[16],char dst[16] )
{
  if( (ULINT)inet_network(src) > (ULINT)inet_network(dst) )
    return OK;
  else
    return ERR;
}

UINT S5VerifyBind(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri )
{

  if( STREQ(ci->udpSrcAddr,ri->DstAddr,sizeof(ci->udpSrcAddr) - 1) && (ci->udpSrcPort == ri->DstPort) )
    return OK;
  else if ( STREQ(ri->DstAddr,"0.0.0.0",sizeof("0.0.0.0") - 1) && (ci->udpSrcPort == ri->DstPort) )
    return OK;
  else
    return ERR;
}

inline UINT S5IfMatch(char ip[16])
{
  UINT count;


  for(count=0;count<NInterF;count++) {
    if( (ULINT)(inet_network(S5Interface[count]->IP) & inet_network(S5Interface[count]->NetMask)) == 
        (ULINT)(inet_network(ip) & inet_network(S5Interface[count]->NetMask)) )
      return count;
  }

  return -1;
}


UINT FileCheck( char *group, char *user )
{
  FILE *groupFile;

  UINT i,l;

  pid_t pid;

  char groupFileName[192];
  char userName[64];

  char logString[128];

   /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  if( SS5SocksOpt.Profiling == FILE_PROFILING ) {
    strncpy(groupFileName,S5ProfilePath,sizeof(groupFileName));
    STRSCAT(groupFileName,"/");
    STRSCAT(groupFileName,group);

    if( (groupFile = fopen(groupFileName,"r")) == NULL ) {
      ERRNO(pid)
      return ERR;
    }

    /*
     *    Check for username into configuration file for access profile
     */
    while( fscanf(groupFile,"%64s",userName) != EOF ) {
      if( userName[0] != '#' )
        if( STRCASEEQ(userName,user,64) ) {
          fclose(groupFile);
          return OK;
        }
    }
    fclose(groupFile);
    return ERR;
  }
  return ERR;
}


/* ***************************** HASH for ROUTING TABLE **************************** */
inline UINT S5RouteHash( ULINT sa )
{
  return ( sa % MAXROUTELIST );
}

ULINT GetRoute(ULINT sa, ULINT da, char *uname)
{
  UINT index,nm;
  UINT err = ERR;
  struct _S5RouteNode *node;
  ULINT n_sa;


  /*
   * Look for src route
   */
  for(nm=0;nm<=32;nm +=1) {
    if( nm < 32)
      n_sa=((sa >> nm) << nm);
    else
      n_sa=0;
    index=S5RouteHash( n_sa );

    if( S5RouteList[index] != NULL ) {
      node=S5RouteList[index];

      do {
        if( (node->SrcAddr == n_sa) && (node->Mask == (nm)) && (node->sd == SRC_ROUTE) ) {
  
          if( node->Group[0] != '-' ) {
            /*
             * Look for username into group (file or directory) defined in permit line
             */
            if( SS5SocksOpt.Profiling == FILE_PROFILING )
              err=FileCheck(node->Group,uname);
            else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
              err=DirectoryCheck(node->Group,uname);
            if( err ) {
              return node->SrcIf;
            }
          }
          else
            return node->SrcIf;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  /*
   * Look for dst route
   */
  for(nm=0;nm<=32;nm +=1) {
    if( nm < 32)
      n_sa=((da >> nm) << nm);
    else
      n_sa=0;
    index=S5RouteHash( n_sa );

    if( S5RouteList[index] != NULL ) {
      node=S5RouteList[index];

      do {
        if( (node->SrcAddr == n_sa) && (node->Mask == (nm)) && (node->sd == DST_ROUTE) ) {
  
          if( node->Group[0] != '-' ) {
            /*
             * Look for username into group (file or directory) defined in permit line
             */
            if( SS5SocksOpt.Profiling == FILE_PROFILING )
              err=FileCheck(node->Group,uname);
            else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
              err=DirectoryCheck(node->Group,uname);
            if( err ) {
              return node->SrcIf;
            }
          }
          else
            return node->SrcIf;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  return ERR;
}


UINT DelRoute(ULINT sa, ULINT si, char *group, UINT mask, UINT sd )
{
  int index;
  struct _S5RouteNode *node, *prevnode=NULL;

  index=S5RouteHash( sa );

  node=S5RouteList[index];

  if( node == NULL )
    return ERR;

  if( (node->SrcAddr == sa) && (node->Mask == mask) ) {
    if( node->next == NULL ) {

      free(node);
      S5RouteList[index]=NULL;
      return OK;
    }
    else {
      S5RouteList[index]=node->next;
      free(node);
      return OK;
    }
  }

  while( node->next != NULL ) {
    prevnode=node;
    node=node->next;

    if( (node->SrcAddr == sa) && (node->Mask == mask) ) {
      if( node->next != NULL )
        prevnode->next=node->next;
      else
        prevnode->next=NULL;

      free(node);
      node=NULL;
      return OK;
    }
  }
  return ERR;
}

UINT AddRoute(UINT ctx, ULINT sa, ULINT si, char *group, UINT mask, UINT sd )
{
  int index;
  struct _S5RouteNode *node, *prevnode;

  index=S5RouteHash( sa );

  if( ctx == OFFLINE )
    node=_tmp_S5RouteList[index];
  else
    node=S5RouteList[index];

  if( node== NULL ) {
    if( (node=(struct _S5RouteNode *)calloc(1,sizeof(struct _S5RouteNode))) == NULL )
      return ERR;
    node->Mask=mask;
    node->SrcAddr=sa;
    node->SrcIf=si;
    node->sd=sd;
    strncpy(node->Group,group,sizeof(node->Group));
    node->next=NULL;

    if( ctx == OFFLINE )
      _tmp_S5RouteList[index]=node;
    else
      S5RouteList[index]=node;
  }
  else {
    if( ctx == OFFLINE )
      node=_tmp_S5RouteList[index];
    else
      node=S5RouteList[index];

    do {
      if( (node->SrcAddr == sa) && (node->Mask == mask) && (node->SrcIf == si) && (node->sd == sd) ) {
        return ERR;
      }
      prevnode=node;
      node=node->next;

    } while(node != NULL );

    if( (node=(struct _S5RouteNode *)calloc(1,sizeof(struct _S5RouteNode))) == NULL )
      return ERR;

    node->Mask=mask;
    node->SrcAddr=sa;
    node->SrcIf=si;
    node->sd=sd;
    strncpy(node->Group,group,sizeof(node->Group));
    node->next=NULL;

    prevnode->next=node;
  }
  return OK;
}

UINT FreeRoute( struct _S5RouteNode **node )
{
  struct _S5RouteNode *lnode;
  struct _S5RouteNode *lnode_prev=NULL;

  lnode=*node;

  if( lnode != NULL ) {
    do {
      while( lnode->next != NULL ) {
        lnode_prev=lnode;
        lnode=lnode->next;
      }
      free(lnode);
      if( lnode_prev != NULL ) {
        lnode_prev->next=NULL;
        lnode=lnode_prev;
        lnode_prev=NULL;
      }
      else
        lnode=NULL;
    } while( (lnode) != NULL );
  }
  *node=NULL;

  return OK;
}

/* ***************************** HASH for UPSTREAM PROXY **************************** */
inline UINT S5ProxyHash( ULINT da, UINT dp )
{
  register UINT i;
  register long int hashVal = 0;
  register UINT len;
  char s[24];

  snprintf(s,sizeof(s),"%lu%u",da,dp);

  len=strlen(s);
  for(i=0; i<len;i++)
    hashVal= 37*hashVal + s[i];

  hashVal %= 997;
  if(hashVal < 0)
    hashVal +=997;

  return hashVal;

}

UINT GetProxy(ULINT da, UINT dp, struct _SS5RequestInfo *ri)
{
  register UINT index,nm;
  register ULINT n_da;
  struct _S5ProxyNode *node;

  for(nm=0;nm<=32;nm++) {
    if( nm < 32)
      n_da=((da >> nm) << nm);
    else
      n_da=0;

    index=S5ProxyHash( n_da, dp );

    if( S5ProxyList[index]!= NULL ) {
      node=S5ProxyList[index];
      do {
        if( (node->DstAddr == n_da) && (node->Mask == nm) && (node->DstPort == dp) ) {
          ri->upDstAddr=node->ProxyAddr;
          ri->upDstPort=node->ProxyPort;
          ri->upSocksVer=node->SocksVer;
          if( node->Type == PROXY ) {
            return OK;
          }
          return ERR_NOPROXY;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  for(nm=0;nm<=32;nm++) {
    if( nm < 32)
      n_da=((da >> nm) << nm);
    else
      n_da=0;

    index=S5ProxyHash( n_da, 0 );

    if( S5ProxyList[index]!= NULL ) {
      node=S5ProxyList[index];
      do {
        if( (node->DstAddr == n_da ) && (node->Mask == nm) && (dp >= node->DstRangeMin) && (dp <= node->DstRangeMax) ) {
          ri->upDstAddr=node->ProxyAddr;
          ri->upDstPort=node->ProxyPort;
          ri->upSocksVer=node->SocksVer;
          if( node->Type == PROXY ) {
            return OK;
          }
          return ERR_NOPROXY; 
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  return ERR;
}

UINT DelProxy(UINT type, ULINT da, ULINT dp, ULINT pa, UINT pp, UINT mask, UINT socksver)
{
  int index;
  struct _S5ProxyNode *node, *prevnode=NULL;

  if( dp > 65535 )
    index=S5ProxyHash( da, 0 );
  else
    index=S5ProxyHash( da, dp );


  node=S5ProxyList[index];

  if( node == NULL )
    return ERR;

  if( (node->Type == type) && (node->DstAddr == da) && (node->Mask == mask) && (dp == node->DstPort) ) {
    if( node->next == NULL ) {

      free(S5ProxyList[index]);
      S5ProxyList[index]=NULL;

      return OK;
    }
    else {
      S5ProxyList[index]=node->next;
      free(S5ProxyList[index]);
      return OK;
    }
  }

  while( node->next != NULL ) {
    prevnode=node;
    node=node->next;

    if( (node->Type == type) && (node->DstAddr == da) && (node->Mask == mask) && (dp == node->DstPort) ) {
      if( node->next != NULL )
        prevnode->next=node->next;
      else
        prevnode->next=NULL;

      free(node);
      node=NULL;
  
      return OK;
    }
  }

  return ERR;
}


UINT AddProxy(UINT ctx,UINT type, ULINT da, ULINT dp, ULINT pa, UINT pp, UINT mask, UINT socksver)
{
  int index;
  struct _S5ProxyNode *node, *prevnode;

  if( dp > 65535 )
    index=S5ProxyHash( da, 0 );
  else
    index=S5ProxyHash( da, dp );

  if( ctx == OFFLINE )
    node=_tmp_S5ProxyList[index];
  else
    node=S5ProxyList[index];

  if( node== NULL ) {
    if( (node=(struct _S5ProxyNode *)calloc(1,sizeof(struct _S5ProxyNode))) == NULL )
      return ERR;
    node->Mask=mask;
    node->DstAddr=da;
    node->Type=type;
    node->SocksVer=socksver;

    if( dp > 65535 ) {
      node->DstPort=dp;
      node->DstRangeMax=dp;
      node->DstRangeMax >>= 16;
      node->DstRangeMax <<= 16;
      node->DstRangeMin = dp - node->DstRangeMax;
      node->DstRangeMax >>= 16;

    }
    else
      node->DstPort=dp;

    node->ProxyAddr=pa;
    node->ProxyPort=pp;
    node->next=NULL;

    if( ctx == OFFLINE )
      _tmp_S5ProxyList[index]=node;
    else
      S5ProxyList[index]=node;
  }
  else {
    if( ctx == OFFLINE )
      node=_tmp_S5ProxyList[index];
    else
      node=S5ProxyList[index];

    do {
      if( (node->DstAddr == da) && (node->Mask == mask) && (node->DstPort == dp) ) {
        return ERR;
      }

      prevnode=node;
      node=node->next;

    } while(node != NULL );

    if( (node=(struct _S5ProxyNode *)calloc(1,sizeof(struct _S5ProxyNode))) == NULL )
      return ERR;
    node->Mask=mask;
    node->DstAddr=da;
    node->Type=type;
    node->SocksVer=socksver;

    if( dp > 65535 ) {
      node->DstPort=dp;
      node->DstRangeMax=dp;
      node->DstRangeMax >>= 16;
      node->DstRangeMax <<= 16;
      node->DstRangeMin = dp - node->DstRangeMax;
      node->DstRangeMax >>= 16;
    }
    else
      node->DstPort=dp;

    node->ProxyAddr=pa;
    node->ProxyPort=pp;
    node->next=NULL;

    prevnode->next=node;
  }
  return OK;
}


UINT FreeProxy( struct _S5ProxyNode **node )
{
  struct _S5ProxyNode *lnode;
  struct _S5ProxyNode *lnode_prev=NULL;

  lnode=*node;

  if( lnode != NULL ) {
    do {
      while( lnode->next != NULL ) {
        lnode_prev=lnode;
        lnode=lnode->next;
      }
      free(lnode);
      if( lnode_prev != NULL ) {
        lnode_prev->next=NULL;
        lnode=lnode_prev;
        lnode_prev=NULL;
      }
      else
        lnode=NULL;
    } while( (lnode) != NULL );
  }
  *node=NULL;
  
  return OK;

}

/* ***************************** HASH for METHOD **************************** */
inline UINT S5MethodHash( ULINT sa, UINT sp )
{
  register UINT i,len;
  register int hashVal = 0;
  char s[32];

  snprintf(s,sizeof(s),"%lu%u",sa,sp);

  len=strlen(s);
  for(i=0; i<len;i++)
    hashVal= 37*hashVal + s[i];

  hashVal %= 997;
  if(hashVal < 0)
    hashVal +=997;

  return hashVal;

}

unsigned char GetMethod(ULINT sa, UINT sp)
{
  register UINT index,nm;
  register ULINT n_sa;
  struct _S5MethodNode *node;

  for(nm=0;nm<=32;nm++) {
    if( nm < 32)
      n_sa=((sa >> nm) << nm);
    else
      n_sa=0;

    index=S5MethodHash( n_sa, 0 );

    if( S5MethodList[index]!= NULL ) {
      node=S5MethodList[index];
      do {
        if( (node->SrcAddr == n_sa) && (node->Mask == nm) && (sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax) ) {
          return node->Method;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  for(nm=0;nm<=32;nm++) {
    if( nm < 32)
      n_sa=((sa >> nm) << nm);
    else
      n_sa=0;

    index=S5MethodHash( n_sa, sp );

    if( S5MethodList[index]!= NULL ) {
      node=S5MethodList[index];
      do {
        if( (node->SrcAddr == n_sa) && (node->Mask == nm) && (node->SrcPort == sp) ) {
          return node->Method;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  return ERR;
}


UINT DelMethod(ULINT sa, ULINT sp, UINT me, UINT mask)
{
  int index;
  struct _S5MethodNode *node, *prevnode=NULL;

  if( sp > 65535 ) 
    index=S5MethodHash( sa, 0 );
  else 
    index=S5MethodHash( sa, sp );


  node=S5MethodList[index];

  if( node == NULL )
    return ERR;

  if( (node->SrcAddr == sa) && (node->Mask == mask) && (sp == node->SrcPort) ) {
    if( node->next == NULL ) {

      free(node);
      S5MethodList[index]=NULL;
      return OK;
    }
    else {
      S5MethodList[index]=node->next;
      free(node);
      return OK;
    }
  }

  while( node->next != NULL ) {
    prevnode=node;
    node=node->next;

    if( (node->SrcAddr == sa) && (node->Mask == mask) && (sp == node->SrcPort) ) {
      if( node->next != NULL )
        prevnode->next=node->next;
      else
        prevnode->next=NULL;

      free(node);
      node=NULL;

      return OK;
    }
  }
  return ERR;
}

UINT AddMethod(UINT ctx, ULINT sa, ULINT sp, UINT me, UINT mask)
{
  int index;
  struct _S5MethodNode *node, *prevnode;

  if( sp > 65535 )
    index=S5MethodHash( sa, 0 );
  else 
    index=S5MethodHash( sa, sp );

  if( ctx == OFFLINE )
    node=_tmp_S5MethodList[index];
  else
    node=S5MethodList[index];

  if( node == NULL ) {
    if( (node=(struct _S5MethodNode *)calloc(1,sizeof(struct _S5MethodNode))) == NULL )
      return ERR;

    node->Mask=mask;
    node->SrcAddr=sa;

    if( sp > 65535 ) {
      node->SrcPort=sp;
      node->SrcRangeMax=sp;
      node->SrcRangeMax >>= 16;
      node->SrcRangeMax <<= 16;
      node->SrcRangeMin = sp - node->SrcRangeMax;
      node->SrcRangeMax >>= 16;
    }
    else
      node->SrcPort=sp;

    node->Method=me;
    node->next=NULL;

    if( ctx == OFFLINE )
      _tmp_S5MethodList[index]=node;
    else
      S5MethodList[index]=node;
  }
  else {
    if( ctx == OFFLINE )
      node=_tmp_S5MethodList[index];
    else
      node=S5MethodList[index];

    do {
      if( (node->SrcAddr == sa) && (node->Mask == mask) && (node->SrcPort == sp) ) {
        return ERR;
      }
      prevnode=node;
      node=node->next;

    } while(node != NULL );

    if( (node=(struct _S5MethodNode *)calloc(1,sizeof(struct _S5MethodNode))) == NULL )
      return ERR;
    node->Mask=mask;
    node->SrcAddr=sa;

    if( sp > 65535 ) {
      node->SrcPort=sp;
      node->SrcRangeMax=sp;
      node->SrcRangeMax >>= 16;
      node->SrcRangeMax <<= 16;
      node->SrcRangeMin = sp - node->SrcRangeMax;
      node->SrcRangeMax >>= 16;
    }
    else
      node->SrcPort=sp;

    node->Method=me;
    node->next=NULL;

    prevnode->next=node;
  }
  return OK;
}

UINT FreeMethod( struct _S5MethodNode **node )
{
  struct _S5MethodNode *lnode;
  struct _S5MethodNode *lnode_prev=NULL;

  lnode=*node;

  if( lnode != NULL ) {
    do {
      while( lnode->next != NULL ) {
        lnode_prev=lnode;
        lnode=lnode->next;
      }
      free(lnode);
      if( lnode_prev != NULL ) {
        lnode_prev->next=NULL;
        lnode=lnode_prev;
        lnode_prev=NULL;
      }
      else
        lnode=NULL;
    } while( (lnode) != NULL );
  }
  *node=NULL;
  
  return OK;

}


UINT V52V4Request(struct _SS5Socks5Data *sd, struct _SS5RequestInfo *ri, struct _SS5ClientInfo *ci)
{
  register UINT i;

  UINT v4bytes=0;

  char V4TcpRequest[256];

  memset((char *)V4TcpRequest, 0, sizeof(V4TcpRequest));

  switch( sd->TcpRequest[3] ) {
    case IPV4:
      /*
       * Destination address is dot notation:
       * convert V5 socks request to V4 socks request
       */
      
      V4TcpRequest[0]=4;
      V4TcpRequest[1]=ri->Cmd;
      V4TcpRequest[2]=sd->TcpRequest[8];
      V4TcpRequest[3]=sd->TcpRequest[9];
      V4TcpRequest[4]=sd->TcpRequest[4];
      V4TcpRequest[5]=sd->TcpRequest[5];
      V4TcpRequest[6]=sd->TcpRequest[6];
      V4TcpRequest[7]=sd->TcpRequest[7];

      for(i = 0; (V4TcpRequest[i + 8] = ci->Username[i]); i++ );

      V4TcpRequest[i+8] = '\0';
      
      v4bytes=8+i+1;

    break;

    case IPV6: /* Not supported */
      return ERR;
    break;

    case DOMAIN:
      /*
       * Destination address is FQDN (TODO)
       */
/*      len=(unsigned char)sd->TcpRequest[4] + 5;
      ri->DstPort=0;
      ri->DstPort +=(unsigned char)sd->TcpRequest[len];
      ri->DstPort <<=8;
      ri->DstPort +=(unsigned char)sd->TcpRequest[len+1];

      for(c=0,i=5;i<len;i++,c++ )
        ri->DstAddr[c]=(unsigned char)sd->TcpRequest[i];

      ri->DstAddr[c]='\0';
      ri->ATyp=DOMAIN;
*/
      return ERR;
    break;
  }

  memcpy(sd->TcpRequest,V4TcpRequest, sizeof(V4TcpRequest));

  return v4bytes;
}

UINT V42V5Response(struct _SS5Socks5Data *sd, struct _SS5RequestInfo *ri, struct _SS5ClientInfo *ci)
{
  UINT v4bytes=0;

  char V5TcpResponse[256];

  memset((char *)V5TcpResponse, 0, sizeof(V5TcpResponse));

  switch( ri->ATyp ) {
    case IPV4:
      /*
       * Destination address is dot notation:
       * convert V4 socks reply to V5 socks reply
       */
      V5TcpResponse[0]=ri->Ver;
      V5TcpResponse[1]=sd->Response[1] - 90;
      V5TcpResponse[2]=0;
      V5TcpResponse[3]=ri->ATyp;
      V5TcpResponse[4]=sd->Response[4];
      V5TcpResponse[5]=sd->Response[5];
      V5TcpResponse[6]=sd->Response[6];
      V5TcpResponse[7]=sd->Response[7];
      V5TcpResponse[8]=sd->Response[2];
      V5TcpResponse[9]=sd->Response[3];

      v4bytes=10;

    break;

    case IPV6: /* Not supported */
      return ERR;
    break;

    case DOMAIN:
      /*
       * Destination address is FQDN (TODO)
       */
/*      len=(unsigned char)sd->TcpRequest[4] + 5;
      ri->DstPort=0;
      ri->DstPort +=(unsigned char)sd->TcpRequest[len];
      ri->DstPort <<=8;
      ri->DstPort +=(unsigned char)sd->TcpRequest[len+1];

      for(c=0,i=5;i<len;i++,c++ )
        ri->DstAddr[c]=(unsigned char)sd->TcpRequest[i];

      ri->DstAddr[c]='\0';
      ri->ATyp=DOMAIN;
*/
      return ERR;
    break;
  }

  memcpy(sd->Response,V5TcpResponse, v4bytes);

  return v4bytes;
}




