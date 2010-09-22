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

#ifndef SS5OPENLDAP_H
#define SS5OPENLDAP_H 1

/*
 * SS5: Directory configuration parameters
 */
struct _S5Ldap {
  char IP[16];        /* Directory ip */
  char Port[6];       /* Directory port */
  char Base[64];      /* Directory base */
  char Filter[128];   /* Directory filter */
  char Attribute[32]; /* Directory attribute for FILTER mode */
  char Dn[64];        /* Directory dn */
  char Pass[16];      /* Directory password */
  char NtbDomain[16]; /* Windows netbios domain associated to directory */
} S5Ldap[MAXLDAPSTORE];


UINT
  DirectoryCheck( char *group,
		  char *s5username
);

UINT
  DirectoryQuery( pid_t pid,
                  char *group,
                  char *user,
                  int dirid
);

#endif
