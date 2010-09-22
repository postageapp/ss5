/* Socks Server 5
 * Copyright (C) 2003 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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

#ifndef SS5CORE_H
#define SS5CORE_H 1

#define SS5CCLOSE(n)  S5ChildClose(CONTINUE,n,&SS5ClientInfo); 

#define GETPROXYBYNAME()    { modErr = SS5Modules.mod_socks5.GetProxy(S5StrHash(SS5RequestInfo.DstAddr),SS5RequestInfo.DstPort,&SS5RequestInfo);}
#define GETPROXYBYADDRESS() { modErr = SS5Modules.mod_socks5.GetProxy(inet_network(SS5RequestInfo.DstAddr),SS5RequestInfo.DstPort,&SS5RequestInfo);}

#define THREADEXIT()     { if(SS5ProxyData.UdpSend) free(SS5ProxyData.UdpSend); if(SS5ProxyData.UdpRecv) free(SS5ProxyData.UdpRecv); if(SS5ProxyData.Send)    free(SS5ProxyData.Send); if(SS5ProxyData.Recv)    free(SS5ProxyData.Recv); S5ChildClose(CONTINUE,SS5ClientInfo.Socket,&SS5ClientInfo); pthread_exit(THREAD_EXIT); }

#define PROCESSCLOSE()   { S5ChildClose(CONTINUE,SS5ClientInfo.Socket,&SS5ClientInfo); return ERR; }
#define PROCESSEXIT()    S5ChildClose(EXIT,SS5ClientInfo.Socket,&SS5ClientInfo);
#define SS5PCLOSE()      { if( AUTHENRADIUS() && SS5ClientInfo.sid ) { SS5ClientInfo.iPacket=tBR; SS5ClientInfo.oPacket=tBS; S5RadiusAcct(&SS5ClientInfo, 2,  pid); }; if( NOTTHREADED() ) { if( preforkMode ) { PROCESSCLOSE() } else PROCESSEXIT() } else { THREADEXIT() } }

#define UPDATESTAT()    SS5Modules.mod_statistics.Summary(autheErr,authoErr,cmdErr);
#define UPDATEBANDT(n)  LOCKMUTEXCS();SS5Modules.mod_bandwidth.UpdateBandTable(SS5ClientInfo.Username,n);UNLOCKMUTEXCS()


/*
 * Main function: it works to serv client requests
 */
UINT
  S5Core( int cSocket );

UINT
  SrvCore( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd );

UINT
  ListOption( UINT s);

UINT
  ListPeer( UINT s);


#endif
