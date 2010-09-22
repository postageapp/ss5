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

#ifndef SS5MOD_BALANCE_H
#define SS5MOD_BALANCE_H 1

/*
 * Functions definition
 */

UINT
  InitModule(			struct _module *m
);

UINT
  AddVip(			char *real,
				UINT vid,
				UINT index
);

UINT
  FreeConnectionTable (		struct _S5ConnectionEntry *ce
);

UINT
  FreeAffinity( 		struct _S5StickyNode **node
);

UINT
  LoadBalancing(		struct _SS5ClientInfo *ci,
				struct _SS5RequestInfo *ri
);

UINT 
  SrvBalancing( 		struct _SS5ClientInfo *ci, 
				struct _SS5Socks5Data *sd
);

UINT
  S5LeastConnectionReal(	char *s5application
);

UINT
  S5GetRealVid(			char *real
);

UINT
  S5AddConn2Real(		char *real
);

UINT
  S5RemoveConn2Real(		char *real
);

UINT
  S5AddReal2ConnectionTable(	char *real,
				UINT vid,
				UINT index
);

inline UINT
  S5StickyHash(			ULINT srcip
);

ULINT
  S5GetAffinity(		ULINT srcip,
				UINT *ttl_status,
				UINT vid
);

UINT
  S5SetAffinity(		ULINT srcip,
				ULINT dstip,
				UINT vid
);

UINT
  S5RemoveAffinity(		ULINT srcip,
				UINT vid
);

UINT
  Balancing(			struct _SS5ClientInfo *ci,
				struct _SS5Socks5Data *sd
);

#endif
