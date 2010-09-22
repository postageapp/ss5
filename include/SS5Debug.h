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

#ifndef SS5DEBUG_H
#define SS5DEBUG_H 1

inline void
  S5DebugMethodInfo( 	pid_t pid,
                        struct _SS5ClientInfo ci
);

inline void
  S5DebugAuthInfo(	pid_t pid,
                        struct _SS5ClientInfo ci
);

inline void
  S5DebugRequestInfo( 	pid_t pid,
                        struct _SS5RequestInfo ri
);

inline void
 S5DebugUdpRequestInfo( pid_t pid,
                        struct _SS5RequestInfo ri
);

inline void
  S5DebugUpstreamInfo(	pid_t pid,
                        struct _SS5RequestInfo ri
);

inline void
  S5DebugFacilities( 	pid_t pid,
                        struct _SS5Facilities fa
);

inline void
  S5DebugStatistics( 	pid_t pid
);

#endif
