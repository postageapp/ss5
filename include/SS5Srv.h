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

#ifndef SS5SRV_H
#define SS5SRV_H 1

UINT ConnectConsole (char *addr,UINT port ); 

void 
  Usage( 		void
);

int Stat_Conn( char *addr,UINT port );
int Stat_Bind( char *addr,UINT port );
int Stat_Udp( char *addr,UINT port );
int Stat_Authen( char *addr,UINT port );
int Stat_Author( char *addr,UINT port );

int List_Option( char *addr,UINT port, FILE *ou );
int List_Peer( char *addr,UINT port, FILE *ou );
int List_Bandwidth( char *addr,UINT port, FILE *ou );
int List_Authorization( char *addr,UINT port, FILE *ou );
int List_Authcache( char *addr,UINT port );
int List_Route( char *addr,UINT port, FILE *ou );
int List_Proxy( char *addr,UINT port, FILE *ou );
int List_Dump( char *addr,UINT port, FILE *ou );
int List_Method( char *addr,UINT port, FILE *ou );
int List_Virtual( char *addr,UINT port, FILE *ou );

int Disp_Authcache( char *addr,UINT port );
int Disp_Authocache( char *addr,UINT port );
int Disp_Virtualcache( char *addr,UINT port );

int Show_Conn( char *addr,UINT port );
int Show_Bind( char *addr,UINT port );
int Show_Udp( char *addr,UINT port );
int Show_Authen( char *addr,UINT port );
int Show_Author( char *addr,UINT port );


int Del_Bandwidth( char *addr, UINT port, char *user, char *lncon, char *lband );
int Add_Bandwidth( char *addr, UINT port,char *user, char *lncon, char *lband );

int Add_Method( char *addr, UINT port,char *sa, char *sp, char *me );
int Del_Method( char *addr, UINT port,char *sa, char *sp, char *me );

int Add_Route( char *addr, UINT port,char *sa, char *si, char *grp, char *dir );
int Del_Route( char *addr, UINT port,char *sa, char *si, char *grp, char *dir );

int Add_Permit( char *addr, UINT port,char *me, char *sa, char *sp, char *da, char *dp, char *fu, char *grp, char *ba, char *ed, UINT f );
int Del_Permit( char *addr, UINT port,char *me, char *sa, char *sp, char *da, char *dp, char *fu, char *grp, char *ba, char *ed, UINT f );

int Add_Dump( char *addr,UINT port, char *da, char *dp, char *dm );
int Del_Dump( char *addr,UINT port, char *da, char *dp, char *dm );

int Add_Proxy( char *addr,UINT port, char *da, char *dp, char *pa, char *pp, char *sv, UINT f );
int Del_Proxy( char *addr,UINT port, char *da, char *dp, char *pa, char *pp, char *sv, UINT f );

int Write_Config( char *f );

#endif
