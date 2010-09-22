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

#ifndef SS5MOD_BANDWIDTH
#define SS5MOD_BANDWIDTH 1

/*
 * Evaluate bandwidth utilization
 */
  UINT
    Bandwidth(	struct timeval tv,
		struct _SS5ProxyData *pd,
		struct _SS5Facilities *fa
);

/*
 * Slave functions: manage bandwidth table feature
 */
inline UINT
  S5BandTableHash(      char *u
);

UINT
  GetBandTableC(         char *u
);

UINT
  CheckBandTableC(       char *u
);

ULINT
  GetBandTableB(         char *u
);

UINT
  UpdateBandTable(      char *u,
                        int n
);

UINT
  AddBandTable(         UINT ctx,
                        char *u,
                        int ln,
                        ULINT lb
);

UINT 
  DelBandTable(	char *u);

UINT 
  TransfBandTable( 	struct _S5BandTableNode *node
);

UINT
  FreeBandTable(        struct _S5BandTableNode **node
);

UINT
  SrvBandwidth( 	struct _SS5ClientInfo *ci, 
			struct _SS5Socks5Data *sd
);

UINT 
  S5BrowseBandTable( 	char *buf, 
			struct _S5BandTableNode *node
);

UINT 
  CopyBandTable(	char *u, 
			int n
);

#endif
