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

#ifndef SS5MOD_SOCKS5_H
#define SS5MOD_SOCKS5_H 1

#define BIND_TIMEOUT    120     /* Seconds */
#define UDP_TIMEOUT     60      /* Seconds */
#define BEGIN_STREAM     0
#define CONTINUE_STREAM  1
#define END_STREAM       2

enum ERR_PROXY {
  ERR_NOPROXY = 0
};

enum ERR_SOCKS5 {
  ERR_DUPLINES= -1
};

UINT   NMethodList,
         _tmp_NMethodList,
          NRouteList,
         _tmp_NRouteList,
          NProxyList,
         _tmp_NProxyList;



UINT
  InitModule( 		struct _module *m
);

UINT
  MethodParsing(	struct _SS5ClientInfo *ci,
			struct _SS5Socks5Data *sd
);

UINT
  RequestParsing(	struct _SS5ClientInfo *ci,
			struct _SS5Socks5Data *sd,
			struct _SS5RequestInfo *ri
);

UINT
  UpstreamServing(	struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Socks5Data *sd
);

UINT
  ConnectServing(	struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Socks5Data *sd
);

UINT
  BindServing(		struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Socks5Data *sd
);

UINT
  UdpAssociateServing(	struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Socks5Data *sd,
			struct _SS5ProxyData *pd
);

UINT
  UdpAssociateResponse(	struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Socks5Data *sd,
			struct _SS5ProxyData *pd
);

UINT 
  SrvSocks5           ( struct _SS5ClientInfo *ci,
                        struct _SS5Socks5Data *sd 
);

UINT 
  V52V4Request(		struct _SS5Socks5Data *sd,
			struct _SS5RequestInfo *ri,
			struct _SS5ClientInfo *ci);

UINT 
  V42V5Response(	struct _SS5Socks5Data *sd,
			struct _SS5RequestInfo *ri,
			struct _SS5ClientInfo *ci);

UINT 
  FileCheck( 		char *group,
			char *user
);

UINT
  AddMethod(		UINT ctx,
                        ULINT sa,
			ULINT sp,
			UINT me,
			UINT mask
);

UINT 
  DelMethod(ULINT sa, ULINT sp, UINT me, UINT mask);



UINT
  FreeMethod(		struct _S5MethodNode **node
);

unsigned char
  GetMethod(		ULINT sa,
			UINT sp
);

UINT
  AddRoute(		UINT ctx,
                        ULINT sa,
			ULINT si,
                        char *group,
			UINT mask,
			UINT sd );

UINT 
  DelRoute(ULINT sa, ULINT si, char *group, UINT mask, UINT sd );

UINT
  FreeRoute( 		struct _S5RouteNode **node
);

ULINT
  GetRoute(		ULINT sa,
  			ULINT da,
                        char *uname
);

UINT
  AddProxy(		UINT ctx,
                        UINT type,
  			ULINT da,
			ULINT dp,
			ULINT pa,
			UINT pp,
			UINT mask,
			UINT socksver );
UINT 
  DelProxy(UINT type, ULINT da, ULINT dp, ULINT pa, UINT pp, UINT mask, UINT socksver);

UINT
  FreeProxy( 		struct _S5ProxyNode **node
);

UINT
  GetProxy(		ULINT da,
			UINT dp,
			struct _SS5RequestInfo *ri
);


UINT
  S5ResolvHostName( 	struct _SS5RequestInfo *ri,
			struct _S5HostList *s5hostlist,
			UINT *s5resolvedhosts
);

UINT
  S5OrderIP(		struct _S5HostList *s5hostlist,
			UINT *s5resolvedhosts
);

UINT
  S5CompIP(		char src[16],
			char dst[16]
);

UINT
  S5GetBindIf(		char *s5application,
			char *s5clientbind
);

UINT
  S5VerifyBind(		struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri
);

inline UINT
  S5IfMatch(		char ip[16]
);

UINT 
  S5BrowseMethodList( 	char *buf, 
			struct _S5MethodNode *node
);

UINT 
  S5BrowseRouteList( 	char *buf,
			struct _S5RouteNode *node
);

UINT 
  S5BrowseProxyList( 	char *buf,
			struct _S5ProxyNode *node
);

#endif
