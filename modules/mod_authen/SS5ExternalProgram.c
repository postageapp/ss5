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
#include "SS5ExternalProgram.h"

UINT S5AuthProgramCheck( struct _SS5ClientInfo *ci, pid_t pid )
{
  char resp[3];
  char prog[1024];

  char tmp[1024];
  UINT i,l;

  char logString[128];

  FILE *stream;
  /* 
   *    Build command line for program execution escaping each
   *    character not alphanumeric
   */
  memset(prog, 0, sizeof(prog));
  memset(tmp, 0, sizeof(tmp));

  strncpy(prog,S5AuthCmd->ProgName,sizeof(S5AuthCmd->ProgName) - 1);
  STRSCAT(prog," '");


  for (i = 0; ci->Username[i]; i++)
    {
      if ( (ci->Username[i] >=48 && ci->Username[i] <=57) || (ci->Username[i] >=65 && ci->Username[i] <=90) || (ci->Username[i] >=97 && ci->Username[i] <=122) )
	tmp[i] = ci->Username[i];
      else
	{
	  tmp[i] = '\\';
	  tmp[i + 1] = ci->Username[i];
	}
    }

  STRSCAT(prog,tmp);
  STRSCAT(prog,"' '");
  memset(tmp, 0, sizeof(tmp)); /* must be reset to null */

  for (i = 0; ci->Password[i]; i++)
    {
      if ( (ci->Password[i] >=48 && ci->Password[i] <=57) || (ci->Password[i] >=65 && ci->Password[i] <=90) || (ci->Password[i] >=97 && ci->Password[i] <=122) )
	tmp[i] = ci->Password[i];
      else
	{
	  tmp[i] = '\\';
	  tmp[i + 1] = ci->Password[i];
	}
    }
  STRSCAT(prog,tmp);
  STRSCAT(prog,"'");

  /* 
   *    Open pipe and fork 
   */
  if( (stream = popen(prog,"r")) == NULL ) {
    ERRNO(pid)
    return ERR;
  }
  /* 
   *    Get standard output from generic external authentication program 
   */
  fscanf(stream,"%2s",resp);

  if( pclose(stream) == -1 ) {
    ERRNO(pid)
  }
  /* 
   *    If standard output is equal to "OK" then authenticaton will be OK too 
   */
  if( STREQ(resp,"OK",sizeof("OK") - 1) )
    return OK;
  else
    return ERR;
}

