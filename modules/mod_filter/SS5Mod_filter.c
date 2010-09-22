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
#include"SS5Mod_filter.h"

UINT InitModule( struct _module *m )
{
  m->Filtering = Filtering;

  return OK;
}

UINT Filtering( struct _SS5ClientInfo *ci, char *fixup, struct _SS5ProxyData *pd )
{
  if( STREQ(fixup,"https",sizeof("https") - 1) ) {
    if( !S5FixupHttps(pd) ) {
      return ERR_HTTP;
    }
  }
  else if( STREQ(fixup,"http",sizeof("http") - 1) ) {
    if( !S5FixupHttp(pd) ) {
      return ERR_HTTPS;
    }
  }
  else if( STREQ(fixup,"smtp",sizeof("smtp") - 1) ) {
    if( !S5FixupSmtp(pd) ) {
      return ERR_SMTP;
    }
  }
  else if( STREQ(fixup,"pop3",sizeof("pop3") - 1) ) {
    if( !S5FixupPop3(pd) ) {
      return ERR_POP3;
    }
  }
  else if( STREQ(fixup,"imap4",sizeof("imap4") - 1) ) {
    if( !S5FixupImap(pd) ) {
      return ERR_IMAP4;
    }
  }
  else if( STREQ(fixup,"icache",sizeof("icache") - 1) ) {
    if( !S5FixupiCache(pd,ci) ) {
      return ERR_ICACHE;
    }
  }
  return OK;
}

UINT S5FixupSmtp( struct _SS5ProxyData *pd )
{
  register UINT idx;
  register UINT offset;
  register UINT len;

  const char s1[] = "helo";
  const char s2[] = "ehlo";

  len=sizeof(s1) - 1;

  for(offset = 0; offset < DATABUF - len; offset++)
  {
    for(idx = 0; idx < len; idx++)
      if( tolower(pd->Recv[offset+idx]) != s1[idx] )
        break;

    if( idx == len ) {
      return OK;
    }
  }

  len = sizeof(s2) - 1;

  for(offset = 0; offset < DATABUF - len; offset++)
  {
    for(idx = 0; idx < len; idx++)
      if( tolower(pd->Recv[offset+idx]) != s2[idx] )
        break;

    if( idx == len ) {
      return OK;
    }
  }
  return ERR;
}

UINT S5FixupPop3( struct _SS5ProxyData *pd )
{
  register UINT idx;
  register UINT offset;
  register UINT len;
  
  const char s[] = "user";

  len = sizeof(s) - 1;

  for(offset = 0; offset < DATABUF - len; offset++)
  {
    for(idx = 0; idx < len; idx++)
      if( tolower(pd->Recv[offset+idx]) != tolower(s[idx]) )
        break;

    if( idx == len ) {
      return OK;
    }
  }
  return ERR;
}

UINT S5FixupImap( struct _SS5ProxyData *pd )
{
  register UINT idx;
  register UINT offset;
  register UINT len;
  
  const char s[] = "capability";

  len = sizeof(s) - 1;

  for(offset = 0; offset < DATABUF - len; offset++)
  {
    for(idx = 0; idx < len; idx++)
      if( tolower(pd->Recv[offset+idx]) != tolower(s[idx]) )
        break;

    if( idx == len ) {
      return OK;
    }
  }
  return ERR;
}

UINT S5FixupHttp( struct _SS5ProxyData *pd )
{
  register UINT idx;
  register UINT offset;
  register UINT len;
  
  char s[] = "User-Agent:";

  len = sizeof(s) - 1;

  for(offset = 0; offset < DATABUF - len; offset++)
  {
    for(idx = 0; idx < len; idx++)
      if( pd->Recv[offset+idx] != s[idx] )
        break;

    if( idx == len ) {
      return OK;
    }
  }
  return ERR;
}

UINT S5FixupHttps( struct _SS5ProxyData *pd )
{
  int sslPacketLen;

  /* 
   *    SSLv2 Record Layer: Client Hello
   * 
   *    Check two records:
   *
   *    sslPacketLen:           must contain the len of the SSL packet
   *    Handshake Message Type: must contain the "Client Hello" message
   */

  sslPacketLen = pd->Recv[1] + 2;

  if( sslPacketLen == pd->TcpRBufLen) {
    if( pd->Recv[2] == CLIENT_HELLO ) {
      return OK;
    }
  }

  /* 
   *    SSLv3 Record Layer: Client Hello
   *    TLSv1 Record Layer: Client Hello
   * 
   *    Check two records:
   *
   *    Length:       must contain the len of the SSL packet
   *    Content Type: must contain the Handshake type
   */
  sslPacketLen = pd->Recv[3];
  sslPacketLen <<= 8;
  sslPacketLen += pd->Recv[4];
  sslPacketLen += 5;

  if( pd->Recv[0] == HANDSHAKE ) {
    if( sslPacketLen == pd->TcpRBufLen ) {
      if( pd->Recv[5] == CLIENT_HELLO ) {
        return OK;
      }
    }
  }

  return ERR;
}


UINT S5FixupiCache( struct _SS5ProxyData *pd, struct _SS5ClientInfo *ci)
{
  register UINT k,i,l;
  
  struct timeval tv;

  fd_set arrayFd;

  struct sockaddr_in da_sin,sa_sin;

  int fd, s;

  UINT icpPlen, len, hc=0; 
 
  ULINT tBR = 0;

  struct _http_request http_request;
  struct _http_header  http_header[32];

  char buf[DATABUF];

  char logString[256];

  pid_t pid;

  /*
   * Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  memset(&http_request,    0,sizeof(struct _http_request));
  memset(&http_header,     0,sizeof(struct _http_header)*MAX_HEADERS);

  /*
   * Look for http GET comand and parse http header
   */
  if( pd->Recv[0] == 'G' && pd->Recv[1] == 'E' && pd->Recv[2] == 'T' && pd->Recv[3] == ' ') {

    /*
     * Parse http request
     */
    S5ParseHttpReq(pd, &http_request);

    if( DEBUG() ) {
      snprintf(logString,128,"[%u] [DEBU] Parsing http request: %s %s %s.", pid,http_request.cmd,http_request.url,http_request.proto );
      LOGUPDATE()
    }  

    /*
     * Parse http headers
     */
    hc = S5ParseHttpHeader(pd, &http_request, (struct _http_header *) &http_header);

    /*
     * Query cache server for URL
     */
    if ( (s = socket(AF_INET,SOCK_DGRAM, 0)) == -1) {
      return ERR;
    }
  
    icpPlen=24+strlen(http_request.icpUrl)+1;
  
    bzero(buf,sizeof(buf));
    buf[0]=0x01;
    buf[1]=0x02;

    SETICPREQ_R(buf,0x00000001,4)
    SETICPLEN_R(buf,icpPlen,2)

    for(k=24;k<icpPlen;k++)
      buf[k]=http_request.icpUrl[k-24];
  
    memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
    da_sin.sin_family      = AF_INET;
    da_sin.sin_port        = htons(3130);
    da_sin.sin_addr.s_addr = inet_addr((char *)SS5SocksOpt.ICacheServer);
  
    len=sizeof(struct sockaddr_in);
  
    /*
     * Send ICP_QUERY packet
     */
    if ( (s = socket(AF_INET,SOCK_DGRAM, 0)) == -1)
      return ERR;
  
    IFLINUX( if( sendto(s, buf, icpPlen, MSG_NOSIGNAL, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )
    IFSOLARIS( if( sendto(s, buf, icpPlen, 0, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )
      snprintf(logString,256,"[%u] [ERRO] Error sending ICP query for %s", pid, http_request.proxyUrl );
      LOGUPDATE()

      close(s);
      return ERR;
    }

    /*
     * Receve ICP response
     */
    FD_ZERO(&arrayFd);
    FD_SET(s,&arrayFd);

    tv.tv_sec  = ICP_QUERY_TIMEOUT;
    tv.tv_usec = 0;

    bzero(buf,icpPlen);

    if( (fd = select(s+1,&arrayFd,NULL,NULL,&tv)) ) {
      if( FD_ISSET(s,&arrayFd) ) {
        if( recvfrom(s,buf,icpPlen-4,0,(struct sockaddr *)&sa_sin,(socklen_t *)&len) == -1 ) {
          snprintf(logString,256,"[%u] [ERRO] Error receiving ICP response for %s.", pid, http_request.proxyUrl );
          LOGUPDATE()

          close(s);
          return ERR;
        }
      }
    }
    else {
      snprintf(logString,256,"[%u] [ERRO] Timeout error receiving ICP response for %s.", pid, http_request.proxyUrl );
      LOGUPDATE()

      close(s);
      return ERR;
    }
  
    close(s);
  
    /*
     * If ICP_HIT, fetch the request from cache server
     */
    if( buf[0] == ICP_HIT ) {
      if( DEBUG() ) {
        snprintf(logString,256,"[%u] [DEBU] ICP query HIT for object %s.", pid,http_request.proxyUrl );
        LOGUPDATE()
      }  
      bzero(buf,sizeof(buf));
      strcpy(buf,http_request.proxyUrl);
  
      for(k=1;k<hc;k++){
        STRSCAT(buf,http_header[k].hn);
        STRSCAT(buf," ");
        STRSCAT(buf,http_header[k].hv);
        STRSCAT(buf,"\n");
      }
      STRSCAT(buf,"\n\0");
    
      if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return ERR;
    
      da_sin.sin_port = htons(3128);
      if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {
        IFLINUX( if( send(s,buf,strlen(buf),MSG_NOSIGNAL) == -1) { )
        IFSOLARIS( if( send(s,buf,strlen(buf),0) == -1) { )
          if( VERBOSE() ) {
            snprintf(logString,128,"[%u] [VERB] Error sending proxy request to proxy cache server %s.",
                     pid,SS5SocksOpt.ICacheServer );
            LOGUPDATE()
          }  
          close(s);
          return ERR;
        }
        i=0;

        /*
         * Send cached object to client
         */
        do {
          bzero(pd->Recv,DATABUF);
          len=recv(s,pd->Recv,DATABUF,0);

          tBR += len;

          if(len>0) {
            memset(pd->Send,0,sizeof(pd->Send));
            memcpy(pd->Send,pd->Recv,len);
            pd->TcpSBufLen = send(ci->Socket,pd->Send,len,SS5_SEND_OPT);
    
            i++;
          }
          else if( len == 0 && i == 0) {
            ; 
          }
          /* Receiving error */
          else if(len == -1) {
            if( VERBOSE() ) {
              snprintf(logString,128,"[%u] [VERB] Error receiving cached object from proxy cache server %s.",
                       pid,SS5SocksOpt.ICacheServer );
              LOGUPDATE()
            }  
          }  
    
        } while(len);
      }
      /* Connection error */
      else {
        if( VERBOSE() ) {
          snprintf(logString,128,"[%u] [VERB] Error connecting to proxy cache server %s.",pid,SS5SocksOpt.ICacheServer );
          LOGUPDATE()
        }
      }
    
      if( VERBOSE() ) {
        snprintf(logString,128,"[%u] [VERB] iCache filter: received %lu bytes from cache server %s.",pid,tBR,SS5SocksOpt.ICacheServer );
        LOGUPDATE()
      }
      pd->TcpRBufLen=0;
      close(s);
    }
  }
  return OK;
}

UINT S5ParseHttpReq(struct _SS5ProxyData *pd, struct _http_request *hr)
{
  register int i,j;

  /*
   * Parse http request
   */
  for(i=0,j=0;pd->Recv[i] != ' ' && i < pd->TcpRBufLen;i++)
    if( j < (sizeof(hr->cmd) - 1) )
      hr->cmd[j++]=pd->Recv[i];
  hr->cmd[j]='\0';

  while(pd->Recv[i]==' ' && i < pd->TcpRBufLen)
    i++;
  for(j=0;pd->Recv[i] != ' ' && i < pd->TcpRBufLen;i++)
    if( j < (sizeof(hr->url) - 1) )
      hr->url[j++]=pd->Recv[i];
  hr->url[j]='\0';

  while(pd->Recv[i]==' ' && i < pd->TcpRBufLen)
    i++;
  for(j=0;pd->Recv[i] != '\n' && i < pd->TcpRBufLen;i++)
    if( j < (sizeof(hr->proto) -1 ) )
      hr->proto[j++]=pd->Recv[i];
  hr->proto[j]='\0';

  return OK;
}

UINT S5ParseHttpHeader(struct _SS5ProxyData *pd, struct _http_request *hr, struct _http_header *hh)
{
  register UINT i=0,j;

  char str_h[128], 
       str_v[DATABUF/2];

  char logString[256];

  int hc=0; 

  pid_t pid;

  /*
   * Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  do {
    for(++i,j=0;pd->Recv[i] != ':' && i < pd->TcpRBufLen;i++)
      if( j < (sizeof(str_h) - 1) )
        str_h[j++]=pd->Recv[i];

    if( i == pd->TcpRBufLen ) break;

    str_h[j++]=pd->Recv[i++];
    str_h[j]='\0';

    if( (hh[hc].hn=calloc(j,sizeof(char))) == NULL )
      return ERR;
    else
      memcpy(hh[hc].hn,str_h,j);

    while(pd->Recv[i]==' ' && i < pd->TcpRBufLen)
      i++;
    for(j=0;pd->Recv[i] != '\n' && i < pd->TcpRBufLen;i++) {
      if( j < (sizeof(str_v) - 1) )
        str_v[j++]=pd->Recv[i];
    }

    if( i == pd->TcpRBufLen ) break;

    str_v[j-1]='\0';

    if( (hh[hc].hv=calloc(j,sizeof(char))) == NULL )
      return ERR;
    else
      memcpy(hh[hc].hv,str_v,j);

    if( DEBUG() ) {
      snprintf(logString,128,"[%u] [DEBU] Parsing http  header: %s.", pid,hh[hc].hv );
      LOGUPDATE()
    }  

   /*
    * Create proxy http request version 1.0 to send to cache server
    * Delete "Connection:" header to avoid keep-alive
    */
    if( strncmp(hh[hc].hn,"Connection:",sizeof("Connection:")) ) {
      if( !strncmp(hh[hc].hn,"Host:",sizeof("Host:")) ) {
        snprintf(hr->proxyUrl,sizeof(hr->proxyUrl) - 1,"GET http://%s%s HTTP/1.0\n",hh[hc].hv,hr->url);
        snprintf(hr->icpUrl,sizeof(hr->icpUrl) - 1,"http://%s%s",hh[hc].hv,hr->url);
      }
      hc++;
    }
  } while( pd->Recv[i+1] != '\n' && i < pd->TcpRBufLen && hc < MAX_HEADERS);

  return hc;
}
