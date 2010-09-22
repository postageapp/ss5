/* Socks Server 5
 * Copyright (C) 2002 - 2010 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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


#include "SS5Main.h"
#include "SS5Mod_authentication.h"
#include "SS5Basic.h"


UINT S5PwdFileCheck( struct _SS5ClientInfo *ci )
{
  FILE *pf;

  char logString[128];

  char user[64];
  char password[64];

  if( (pf = fopen(S5PasswordFile,"r")) == NULL ) {
    ERRNO(0)
    return ERR;
  }

  /* 
   *    Look for username and password into password file 
   */
  while( fscanf(pf,"%63s %63s",user,password) != EOF ) {
    if( STRCASEEQ(ci->Username,user,sizeof(user) - 1) && STREQ(ci->Password,password,sizeof(password) - 1) ) {
      if( fclose(pf) ) {
        ERRNO(0)
        return ERR;
      }
      return OK;
    }
  }

  if( fclose(pf) ) {
    ERRNO(0)
    return ERR;
  }

  return ERR;
}

