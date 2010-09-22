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

#ifndef SS5SERVER_H
#define SS5SERVER_H 1

void
  S5SetStatic(		void
);

void
  S5SetDynamic(		void
);

UINT
  S5ServerClose(	int exitcode
);

inline UINT
  S5ChildClose(		int exitcode,
                        UINT childSocket,
			struct _SS5ClientInfo *ci
);

UINT
  S5UIDSet(		char *username
);

UINT
  S5MakeDaemon(		void
);

UINT
  S5ServerMake(		char *addr,
			UINT port
);

UINT
  S5ServerAccept(	struct sockaddr_in *s5client_ssin,
			int *s5client_socket
);

/*
 * Get network client information from socket after accept syscall
 */
UINT
  S5GetClientInfo(      struct _SS5ClientInfo *ci,
                        UINT s,
                        pid_t pid
);


#endif
