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

#ifndef SS5UTILS_H
#define SS5UTILS_H 1

#define REPCHUNK	4096


UINT
  S5LoadConfig( 	UINT m
);

UINT 
  S5ReceiveConfig(      struct _SS5ClientInfo *ci,
                        struct _SS5Socks5Data *sd 
);

UINT 
  S5PropagateConfig(    void
);

UINT 
  S5LoadPeers(    void
);

UINT 
  S5AllocConfData( void );

UINT
  S5LoadConfData( 	UINT m
);

UINT
  S5SwitchConfData( 	void
);

UINT
  S5FreeConfData( 	void
);

UINT
  S5GetIf(		void
);

UINT
  S5OrderIP(		struct _S5HostList *s5hostlist,
			UINT *s5resolvedhosts
);

UINT
  S5CheckPort(		char *port,
			UINT s5port
);

UINT
  S5GetNetmask(		char *sa
);

void
  S5ReloadConfig(	int sig
);

void
  S5Usage(		void
);

/*int
  S5IfMatch(		char ip[16]
);*/

ULINT
  S5StrHash(		char *s
);

ULINT
  S5GetRange(		char *dp
);

void S5Memcpy(		char *dst,
			char *src,
			ULINT dsti,
			ULINT srci
);

#endif
