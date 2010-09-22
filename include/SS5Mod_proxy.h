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
 * B
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef SS5MOD_PROXY_H
#define SS5MOD_PROXY_H 1

//#define BIND_TIMEOUT    120     /* Seconds */
#define UDP_TIMEOUT     60      /* Seconds */


/*
 * Initialize module context
 */
UINT
  InitModule(		struct _module *m
);

/*
 * Master function: receive and send data tcp/udp
 */
UINT
  ReceivingData(	struct _SS5ClientInfo *ci,
			struct _SS5ProxyData *pd,
                        #ifdef EPOLL_IO
			struct epoll_event *events
                        #else
                        fd_set *s5array
                        #endif
);

UINT
  SendingData(	struct _SS5ClientInfo *ci,
			struct _SS5ProxyData *pd
);

UINT
  UdpReceivingData(	int applicationbindSocket,
			struct _SS5ProxyData *pd
);

UINT
  UdpSendingData(	int applicationSocket,
			struct _SS5RequestInfo *ri,
			struct _SS5ProxyData *pd
);

#endif
