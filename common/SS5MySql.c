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

#ifdef SS5_USE_MYSQL

#include"SS5Main.h"
#include"SS5Mod_authorization.h"
#include"SS5MySql.h"
#include"SS5Mod_log.h"
#include <mysql/mysql.h>

/*#ifdef SOLARIS
  #include<lber.h>
  #define LDAP_DEPRECATED
#endif
*/


UINT MySqlCheck( char *group, char *user )
{
  register UINT idx1;
  register UINT idx2;

  char ntbdomain[64];
  char ntbuser[64];
  char swap[64];

  UINT count;

  int err = ERR;
  int pos = 0,
      gss = 0;
 
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();

  /*
   *    Get netbios domain from username
   */
  ntbdomain[0]='\0';
  ntbuser[0]  ='\0';
  swap[0]  ='\0';

  for(idx1 = 0, idx2 = 0; user[idx1] && (idx1 < (sizeof(ntbuser) - 1)); idx1++ ) {
    if( user[idx1] == '\\' || user[idx1] == '@' ) {
      ntbdomain[idx1] = '\0';
      pos = 1; 
      gss++;
      idx1++;
    }

    if( pos == 0 ) {
      ntbdomain[idx1] = user[idx1];
      ntbuser[idx1] = user[idx1];
      ntbuser[idx1 + 1] = '\0';
    }
    else if( pos == 1 ) {
      ntbuser[idx2++] = user[idx1];
      ntbuser[idx2] = '\0';
    }
  }

  /*
   *    If username in the form user@domain.dom ss5 supposes 
   *    a GSS authentication request
   */
  if( gss ) {
    strncpy(swap,ntbuser,sizeof(swap));
    strncpy(ntbuser,ntbdomain,sizeof(ntbuser));
    strncpy(ntbdomain,swap,sizeof(ntbdomain));
  }
  /*
   *    Look for user into MYSQL UserStore
   */
  err = MySqlQuery( pid, group, ntbuser, count);

  return err;
}

UINT MySqlQuery( pid_t pid, char *group, char *user, int dirid )
{
   MYSQL *conn;
   MYSQL_RES *res;
   MYSQL_ROW row;

   char query[128],
        logString[256];

   snprintf(query,sizeof(query) - 1,"%s '%s'",S5Mysql.SqlString,group);

   conn = mysql_init(NULL);
   
   /* Connect to database */
   if (!mysql_real_connect(conn, S5Mysql.IP,
         S5Mysql.User, S5Mysql.Pass, S5Mysql.DB, 0, NULL, 0)) {
      snprintf(logString, sizeof(logString) - 1,"[%u] [DEBU] %s\n", mysql_error(conn));
      LOGUPDATE()
      return ERR;
   }

   /* send SQL query */
   if (mysql_query(conn, query)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      mysql_close(conn);
      snprintf(logString, sizeof(logString) - 1,"[%u] [DEBU] %s\n", mysql_error(conn));
      LOGUPDATE()
      return ERR;
   }

   res = mysql_use_result(conn);
   
   /* output fields 1 and 2 of each row */
   while ((row = mysql_fetch_row(res)) != NULL) {
     if( STRCASEEQ(user,row[0],64) ) { 
       mysql_free_result(res);
       mysql_close(conn);
       return OK;
     }
   }

   /* Release memory used to store results and close connection */
   mysql_free_result(res);
   mysql_close(conn);

  return ERR;
}
#endif
