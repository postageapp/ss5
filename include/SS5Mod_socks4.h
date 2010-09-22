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

#ifndef SS5MOD_SOCKS4_H
#define SS5MOD_SOCKS4_H 1

#define BIND_TIMEOUT    120     /* Seconds */

struct _SS5Socks4Data {
 char Requ[32];
 char Resp[8];
};


UINT
  InitModule(		struct _module *m
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
  AddRoute(		ULINT sa,
			ULINT si,
			char *group,
			UINT mask,
			UINT sd
);

UINT
  FreeRoute(		struct _S5RouteNode **node
);

ULINT
  GetRoute(		ULINT sa,
  			ULINT da,
			char uname[64]
);

UINT
  S5ResolvHostName(	struct _SS5RequestInfo *ri,
			struct _S5HostList *s5hostlist,
			UINT *s5resolvedhosts
);

UINT
  S5Check_AuthAcl(	struct _SS5ClientInfo *ci
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

#endif
