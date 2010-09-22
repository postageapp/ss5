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

#ifndef SS5MOD_DUMP_H
#define SS5MOD_DUMP_H 1

#define RX              0
#define TX              1
#define RTX             2

#define MAXDUMPLIST     997     /* Max dump list loadable */


enum ERR_DUMP {
     ERR_NODUMPFOUND= -1
};

UINT      NDumpList,
            _tmp_NDumpList;



UINT
  InitModule( 		struct _module *m
);

UINT
  WritingDump( 		FILE *df,
			struct _SS5ProxyData *pd,
			UINT dm
);

UINT
  OpenDump( 		FILE **df,
                        struct _SS5ClientInfo *ci
);

UINT
  CloseDump( 		FILE *df
);

inline UINT
  S5DumpHash(           ULINT da,
                        UINT dp
);

UINT
  GetDump(		ULINT da,
			UINT dp,
			struct _SS5DumpInfo *di
);

UINT
  AddDump(		UINT ctx,
                        ULINT da,
			ULINT dp,
			UINT dm,
			UINT mask
);

UINT 
  DelDump(              ULINT da, 
                        ULINT dp, 
                        UINT mask
);

UINT
  FreeDump( 		struct _S5DumpNode **node
);

UINT
  S5BrowseDumpList( 	char *buf, 
			struct _S5DumpNode *node
);

UINT 
  SrvDump( 		struct _SS5ClientInfo *ci, 
			struct _SS5Socks5Data *sd
);

UINT 
  ListDump(             UINT s
);

#endif
