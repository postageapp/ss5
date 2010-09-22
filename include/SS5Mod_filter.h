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

#ifndef SS5MOD_FILTER_H
#define SS5MOD_FILTER_H 1

#define CLIENT_HELLO    0x01
#define HANDSHAKE       0x16
#define ICP_HIT         0x02

#define ICP_QUERY_TIMEOUT	10
#define MAX_HEADERS		32

#define SETICPREQ_R(x,y,z) for(i=0;i<4;i++) { x[3-i+z]=(y & (0x000000FF << (i*8))) >> (i*8); };
#define SETICPLEN_R(x,y,z) for(i=0;i<2;i++) { x[1-i+z]=(y & (0x00FF << (i*8))) >> (i*8); };

char *ss5ver=SS5_VERSION;

enum ERR_FILTER {
  ERR_ICACHE=   -6,
  ERR_HTTP=     -5,
  ERR_HTTPS=    -4,
  ERR_SMTP=     -3,
  ERR_POP3=     -2,
  ERR_IMAP4=    -1
};

struct _S5Fixup {
  UINT Status;
  UINT Http;
  UINT Https;
  UINT Smtp;
  UINT Pop3;
  UINT Imap;
  UINT ICache;
};


struct _http_request {
  char cmd[8];
  char url[256];
  char proto[16];
  char icpUrl[256];
  char proxyUrl[256];
};

struct _http_header {
  char *hn;     /* Header name */
  char *hv;     /* Header value */
};

/*
 * Initialize module context
 */
UINT
  InitModule(           struct _module *m
);

/*
 * Master function: does filtering work
 */
UINT
  Filtering(	struct _SS5ClientInfo *ci, char *s, struct _SS5ProxyData *pd
);


/*
 * Slave functions: manage fixup features:
 *
 *   Htto
 *   Httos
 *   Smtp
 *   Pop3
 *   Imap
 */
UINT
  S5FixupHttp(	struct _SS5ProxyData *pd );

UINT
  S5FixupHttps( struct _SS5ProxyData *pd );

UINT
  S5FixupSmtp ( struct _SS5ProxyData *pd );

UINT
  S5FixupPop3 ( struct _SS5ProxyData *pd );

UINT
  S5FixupImap ( struct _SS5ProxyData *pd );

UINT 
  S5FixupiCache( struct _SS5ProxyData *pd, struct _SS5ClientInfo *ci );

UINT
  S5ParseHttpReq( struct _SS5ProxyData *pd, struct _http_request *hr );

UINT
  S5ParseHttpHeader( struct _SS5ProxyData *pd, struct _http_request *hr, struct _http_header *hh );
#endif
