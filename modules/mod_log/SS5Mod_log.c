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


#include"SS5Main.h"
#include"SS5Mod_log.h"

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  char timeLog[32];

  time_t now = time(NULL);

  m->Logging = Logging;

  strftime(timeLog,sizeof(timeLog),"%d/%b/%Y:%H:%M:%S %Z",localtime(&now));
  /* 
   *     If set, log into syslog 
   */
  if( SYSLOG() ) {
    ; /*    VOID    */
  }
  else {
    if( (S5LogFile = fopen(S5LoggingFile,"a+")) == NULL ) {
      perror("[ERRO] Error opening log file$\nSystem Error: \n");
      return ERR;
    }
    fflush(S5LogFile);
  }

  return OK;
}

UINT Logging( char *logString )
{
  char timeLog[32];

  time_t now = time(NULL);

  if( NOTMUTE() ) {
    if( SYSLOG() ) {
      syslog(SS5SocksOpt.SyslogFa | SS5SocksOpt.SyslogLe," %s\n",logString);
    }
    else {
      strftime(timeLog,sizeof(timeLog),"%d/%b/%Y:%H:%M:%S %Z",localtime(&now));
      fprintf(S5LogFile,"[%s] ",timeLog);
      fprintf(S5LogFile,"%s\n",logString);
      fflush(S5LogFile);
    }
  }
  return OK;
}

UINT S5LogFileClose( void )
{
  if( fclose(S5LogFile) ) {
    perror("[ERRO] Error closing log file$\nSystem Error: \n");
    return ERR;
  }
  return OK;
}
