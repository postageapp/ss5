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
#include"SS5Defs.h"
#include"SS5Mod_proxy.h"

#ifdef SS5_USE_GSSAPI
#include"SS5GSSApi.h"
#endif

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->ReceivingData = ReceivingData;
  m->SendingData   = SendingData;
  m->UdpReceivingData = UdpReceivingData;
  m->UdpSendingData   = UdpSendingData;
  
  return OK;
}


UINT 
  IFEPOLL( ReceivingData( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd, struct epoll_event *events ) )
  IFSELECT( ReceivingData( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd, fd_set *s5array ) )
{
  register UINT i;

  UINT len=0;

  unsigned char *oubuf;

  unsigned char gssHeader[4];

  /* 
   * Receive data from client
   */
  IFEPOLL( if( events[0].data.fd == ci->Socket ) { )
  IFSELECT( if( FD_ISSET(ci->Socket,s5array) ) { )

    pd->Fd = 0;

#ifdef SS5_USE_GSSAPI
   /*
    * If GSS method, decode proxy data received from client
    */
    if( GSSAPI() && GSSINTEGRITY() ) {

     /*
      * Read GSS Header from the beginning of the receive queue
      */
      pd->TcpRBufLen=recv(ci->Socket,gssHeader,sizeof(gssHeader),MSG_PEEK);
      GET_GSSHEADER_LEN(gssHeader,len,GSS_OFFSET_HLEN)
      len +=4; 

     /*
      * If token is bigger then default buffer size, realloc proxy data buffer
      */
      if( (len > pd->BufSize) && (len < MAX_GSSTOKEN_SIZE) ) {
        pd->Recv=realloc(pd->Recv,(len));
        pd->Send=realloc(pd->Send,(len));
        pd->BufSize=len;
      }

     /*
      * Receive GSS 0x03 token
      */
      memset(pd->Recv,0,pd->BufSize);
      pd->TcpRBufLen = recv(ci->Socket,(void *)pd->Recv,len,0);

      if( (len=pd->TcpRBufLen) ) {
        if( S5GSSApiDecode(ci->GssContext, ci->GssEnc, pd->Recv, &oubuf, &len) ) {

          memcpy(pd->Recv,oubuf,len);
          free(oubuf);
          pd->TcpRBufLen=len;
        }
        else
          return ERR;
      }
    }
    else {
#endif
      memset(pd->Recv,0,pd->BufSize);
      pd->TcpRBufLen = recv(ci->Socket,(void *)pd->Recv,pd->BufSize,0);
#ifdef SS5_USE_GSSAPI
    }
#endif
  }

  /* 
   * Receive data from application
   */
  IFEPOLL( else if( events[0].data.fd == ci->appSocket ) { )
  IFSELECT( else if( FD_ISSET(ci->appSocket,s5array) ) { )
    memset(pd->Recv,0,pd->BufSize);
    pd->TcpRBufLen = recv(ci->appSocket,pd->Recv,pd->BufSize,0);
    pd->Fd = 1;
  }
  return OK;
} 

UINT 
SendingData( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd )
{
  int len;

  unsigned char *oubuf;

  if( pd->Fd == 1 ) {

    memset(pd->Send,0,pd->BufSize);
    memcpy(pd->Send,pd->Recv,pd->TcpRBufLen);

#ifdef SS5_USE_GSSAPI
   /*
    * If GSS method and at least INTEGRITY is asked for, encode proxy data before sending to client
    */
    if( GSSAPI() && GSSINTEGRITY() ) {
      if( (len=pd->TcpRBufLen) ) {
        if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, pd->Send, &oubuf, &len) ) {

          memcpy(pd->Send,oubuf,len);
          free(oubuf);

          pd->TcpRBufLen=len;
        }
        else
          return ERR;
      }
    }
#endif

    pd->TcpSBufLen = send(ci->Socket,pd->Send,pd->TcpRBufLen,SS5_SEND_OPT);
  }
  else {
    memset(pd->Send,0,pd->BufSize);
    memcpy(pd->Send,pd->Recv,pd->TcpRBufLen);
    pd->TcpSBufLen = send(ci->appSocket,pd->Send,pd->TcpRBufLen,SS5_SEND_OPT);
  }

  return OK;
}

UINT 
UdpReceivingData( int appSocket, struct _SS5ProxyData *pd )
{
  UINT len;
  UINT fd;

  struct timeval tv;

  fd_set arrayFd;

  struct sockaddr_in applicationSsin;

  char logString[128];

  pid_t pid;

  IFEPOLL( struct epoll_event ev; )
  IFEPOLL( struct epoll_event events[5]; )
  IFEPOLL( int nfds; )
  IFEPOLL( int kdpfd; )

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  bzero((char *)&applicationSsin, sizeof(struct sockaddr_in));

  len = sizeof(struct sockaddr_in);
  memset(pd->UdpRecv,0,sizeof(pd->UdpBufSize));

  IFSELECT( FD_ZERO(&arrayFd); )
  IFSELECT( FD_SET(appSocket,&arrayFd); )

  IFSELECT( tv.tv_sec  = UDP_TIMEOUT; )
  IFSELECT( tv.tv_usec = 0; )

  IFEPOLL( kdpfd=epoll_create(5); )
  IFEPOLL( ev.events = EPOLLIN; )
  IFEPOLL( ev.data.fd = appSocket; )
  IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, appSocket, &ev); )


  IFSELECT( if( (fd = select(appSocket+1,&arrayFd,NULL,NULL,&tv)) ) { )
  IFEPOLL(  if( (nfds = epoll_wait(kdpfd, events, 5, UDP_TIMEOUT*1000)) ) { )

  IFSELECT( if( FD_ISSET(appSocket,&arrayFd) ) { )
  IFEPOLL(  if( events[0].data.fd == appSocket ) { )
      if( (pd->UdpRBufLen=recvfrom(appSocket,pd->UdpRecv,pd->UdpBufSize,0,(struct sockaddr *)&applicationSsin,
          (socklen_t *)&len)) == -1 ) {

        ERRNO(pid)
        IFEPOLL( close(kdpfd); )
        return ERR;
      }
    }
  }
  else {
    /*
     *    Timeout expired receiving data from remote application
     */
    IFEPOLL( close(kdpfd); )
    return (-1 * S5REQUEST_TTLEXPIRED);
  }

  IFEPOLL( close(kdpfd); )
  return OK;
}

UINT 
UdpSendingData( int appSocket, struct _SS5RequestInfo *ri , struct _SS5ProxyData *pd  )
{
  UINT len;

  char logString[128];

  pid_t pid;

  struct sockaddr_in applicationSsin;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  len = sizeof(struct sockaddr_in);

  memset((char *)&applicationSsin, 0, sizeof(struct sockaddr_in));
  applicationSsin.sin_family      = AF_INET;
  applicationSsin.sin_port        = htons(ri->udpDstPort);
  applicationSsin.sin_addr.s_addr = inet_addr(ri->udpDstAddr);

  if( (pd->UdpSBufLen=sendto(appSocket,pd->UdpSend,pd->UdpSBufLen,0,(struct sockaddr *)&applicationSsin,
      (socklen_t)len)) == -1 ) {

    ERRNO(pid)
    return ERR;
  }

  return OK;
}
