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
#include"SS5Mod_statistics.h"

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->Statistics = Statistics;
  m->Summary = Summary;

  return OK;
}


UINT Statistics( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  char *httpResponse;

  if( STREQ(sd->MethodRequest,"GET /counter=CONNECT HTTP/1.",sizeof("GET /counter=CONNECT HTTP/1.") - 1) ) {
    /*
     *    Create response
     */
    if( (httpResponse=(char *)calloc((128),sizeof(char))) == NULL )
      return ERR;

    snprintf(httpResponse,128 - 1,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",
                                                           SS5Statistics.V5Total_Connect,
                                                           SS5Statistics.V4Total_Connect,
                                                           SS5Statistics.V5Normal_Connect,
                                                           SS5Statistics.V4Normal_Connect,
                                                           SS5Statistics.V5Failed_Connect,
                                                           SS5Statistics.V4Failed_Connect,
                                                           SS5Statistics.V5Current_Connect,
                                                           SS5Statistics.V4Current_Connect);

    /*
     *    Send response
     */
    if( send(ci->Socket,httpResponse,strlen(httpResponse),SS5_SEND_OPT) == -1) {
      free(httpResponse); 
      return ERR;
    }
    else {
      fcntl(ci->Socket,F_SETFL,O_NONBLOCK);
      recv(ci->Socket,httpResponse,128 - 1,0);
      free(httpResponse); 
    return OK;
    }
  }
  else if( STREQ(sd->MethodRequest,"GET /counter=BIND HTTP/1.",sizeof("GET /counter=BIND HTTP/1.") - 1) ) {
    /*
     * Create response
     */
    if( (httpResponse=(char *)calloc((128),sizeof(char))) == NULL )
      return ERR;

    snprintf(httpResponse,128 - 1,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",SS5Statistics.V5Total_Bind,
                                                           SS5Statistics.V4Total_Bind,
                                                           SS5Statistics.V5Normal_Bind,
                                                           SS5Statistics.V4Normal_Bind,
                                                           SS5Statistics.V5Failed_Bind,
                                                           SS5Statistics.V4Failed_Bind,
                                                           SS5Statistics.V5Current_Bind,
                                                           SS5Statistics.V4Current_Bind);

    /*
     * Send response
     */
    if( send(ci->Socket,httpResponse,strlen(httpResponse),SS5_SEND_OPT) == -1) {
      free(httpResponse); 
      return ERR;
    }
    else {
      fcntl(ci->Socket,F_SETFL,O_NONBLOCK);
      recv(ci->Socket,httpResponse,128 - 1,0);
      free(httpResponse); 
    return OK;
    }
  }
  else if( STREQ(sd->MethodRequest,"GET /counter=UDP HTTP/1.",sizeof("GET /counter=UDP HTTP/1.") - 1) ) {
    /*
     * Create response
     */
    if( (httpResponse=(char *)calloc((128),sizeof(char)) ) == NULL )
      return ERR;

    snprintf(httpResponse,128 - 1,"%lu\n%lu\n%lu\n%lu\n",SS5Statistics.V5Total_Udp,
                                                           SS5Statistics.V5Normal_Udp,
                                                           SS5Statistics.V5Failed_Udp,
                                                           SS5Statistics.V5Current_Udp);

    /*
     * Send response
     */
    if( send(ci->Socket,httpResponse,strlen(httpResponse),SS5_SEND_OPT) == -1) {
      free(httpResponse); 
      return ERR;
    }
    else {
      fcntl(ci->Socket,F_SETFL,O_NONBLOCK);
      recv(ci->Socket,httpResponse,128 - 1,0);
      free(httpResponse); 
    return OK;
    }
  }
  else if( STREQ(sd->MethodRequest,"GET /counter=AUTHEN HTTP/1.",sizeof("GET /counter=AUTHEN HTTP/1.") - 1) ) {
    /*
     * Create response
     */
    if( (httpResponse=(char *)calloc((256),sizeof(char))) == NULL )
      return ERR;

    snprintf(httpResponse,256 - 1,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",
                                                           SS5Statistics.Total_Auth_File,
                                                           SS5Statistics.Total_Auth_EAP,
                                                           SS5Statistics.Total_Auth_PAM,
                                                           SS5Statistics.Normal_Auth_File,
                                                           SS5Statistics.Normal_Auth_EAP,
                                                           SS5Statistics.Normal_Auth_PAM,
                                                           SS5Statistics.Failed_Auth_File,
                                                           SS5Statistics.Failed_Auth_EAP,
                                                           SS5Statistics.Failed_Auth_PAM,
                                                           SS5Statistics.Current_Auth_File,
                                                           SS5Statistics.Current_Auth_EAP,
                                                           SS5Statistics.Current_Auth_PAM);

    /*
     * Send response
     */
    if( send(ci->Socket,httpResponse,strlen(httpResponse),SS5_SEND_OPT) == -1) {
      free(httpResponse); 
      return ERR;
    }
    else {
      fcntl(ci->Socket,F_SETFL,O_NONBLOCK);
      recv(ci->Socket,httpResponse,256 - 1,0);
      free(httpResponse); 
    return OK;
    }
  }
  else if( STREQ(sd->MethodRequest,"GET /counter=AUTHOR HTTP/1.",sizeof("GET /counter=AUTHOR HTTP/1.") - 1) ) {
    /*
     * Create response
     */
    if( (httpResponse=(char *)calloc((128),sizeof(char))) == NULL )
      return ERR;

    snprintf(httpResponse,128 - 1,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",
                                                           SS5Statistics.Total_Author_File,
                                                           SS5Statistics.Total_Author_Ldap,
                                                           SS5Statistics.Normal_Author_File,
                                                           SS5Statistics.Normal_Author_Ldap,
                                                           SS5Statistics.Failed_Author_File,
                                                           SS5Statistics.Failed_Author_Ldap,
                                                           SS5Statistics.Current_Author_File,
                                                           SS5Statistics.Current_Author_Ldap);

    /*
     * Send response
     */
    if( send(ci->Socket,httpResponse,strlen(httpResponse),SS5_SEND_OPT) == -1) {
      free(httpResponse); 
      return ERR;
    }
    else {
      fcntl(ci->Socket,F_SETFL,O_NONBLOCK);
      recv(ci->Socket,httpResponse,128 - 1,0);
      free(httpResponse); 
    return OK;
    }
  }

  return ERR;
}

UINT Summary( UINT autheerr, UINT authoerr, UINT cmderr )
{
  /*
  * Using threaded mode, ss5 updates socks requests statistics
  */
  if( THREADED() ) {
    switch( autheerr ) {
      case AFN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Auth_File++;   SS5Statistics.Normal_Auth_File++;
        if( SS5Statistics.Current_Auth_File )
          SS5Statistics.Current_Auth_File--;
        pthread_mutex_unlock( &CSMutex );    break;
      case AFF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Auth_File++;   SS5Statistics.Failed_Auth_File++;
        if( SS5Statistics.Current_Auth_File )
          SS5Statistics.Current_Auth_File--;
        pthread_mutex_unlock( &CSMutex );    break;
      case AEN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Auth_EAP++;    SS5Statistics.Normal_Auth_EAP++;
        if( SS5Statistics.Current_Auth_EAP )
          SS5Statistics.Current_Auth_EAP--;
        pthread_mutex_unlock( &CSMutex );    break;
      case AEF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Auth_EAP++;    SS5Statistics.Failed_Auth_EAP++;
        if( SS5Statistics.Current_Auth_EAP )
          SS5Statistics.Current_Auth_EAP--;
        pthread_mutex_unlock( &CSMutex );    break;
      case APN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Auth_PAM++;    SS5Statistics.Normal_Auth_PAM++;
        if( SS5Statistics.Current_Auth_PAM )
          SS5Statistics.Current_Auth_PAM--;
        pthread_mutex_unlock( &CSMutex );    break;
      case APF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Auth_PAM++;    SS5Statistics.Failed_Auth_PAM++;
        if( SS5Statistics.Current_Auth_PAM )
          SS5Statistics.Current_Auth_PAM--;
        pthread_mutex_unlock( &CSMutex );    break;
    }

    switch( authoerr ) {
      case HFN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Author_File++;    SS5Statistics.Normal_Author_File++;
        if( SS5Statistics.Current_Author_File )
          SS5Statistics.Current_Author_File--;
        pthread_mutex_unlock( &CSMutex );    break;
      case HFF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Author_File++;    SS5Statistics.Failed_Author_File++;
        if( SS5Statistics.Current_Author_File )
          SS5Statistics.Current_Author_File--;
        pthread_mutex_unlock( &CSMutex );    break;
      case HLN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Author_Ldap++;    SS5Statistics.Normal_Author_Ldap++;
        if( SS5Statistics.Current_Author_Ldap )
          SS5Statistics.Current_Author_Ldap--;
        pthread_mutex_unlock( &CSMutex );    break;
      case HLF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.Total_Author_Ldap++;    SS5Statistics.Failed_Author_Ldap++;
        if( SS5Statistics.Current_Author_Ldap )
          SS5Statistics.Current_Author_Ldap--;
        pthread_mutex_unlock( &CSMutex );    break;
    }

    switch( cmderr ) {
      case V4CN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V4Total_Connect++;    SS5Statistics.V4Normal_Connect++;
        if( SS5Statistics.V4Current_Connect )
          SS5Statistics.V4Current_Connect--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V4CF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V4Total_Connect++;    SS5Statistics.V4Failed_Connect++;
        if( SS5Statistics.V4Current_Connect )
          SS5Statistics.V4Current_Connect--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V4BN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V4Total_Bind++;       SS5Statistics.V4Normal_Bind++;
        if( SS5Statistics.V4Current_Bind )
          SS5Statistics.V4Current_Bind--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V4BF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V4Total_Bind++;       SS5Statistics.V4Failed_Bind++;
        if( SS5Statistics.V4Current_Bind )
          SS5Statistics.V4Current_Bind--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V5CN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V5Total_Connect++;    SS5Statistics.V5Normal_Connect++;
        if( SS5Statistics.V5Current_Connect )
          SS5Statistics.V5Current_Connect--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V5CF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V5Total_Connect++;    SS5Statistics.V5Failed_Connect++;
        if( SS5Statistics.V5Current_Connect )
          SS5Statistics.V5Current_Connect--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V5BN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V5Total_Bind++;       SS5Statistics.V5Normal_Bind++;
        if( SS5Statistics.V5Current_Bind )
          SS5Statistics.V5Current_Bind--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V5BF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V5Total_Bind++;       SS5Statistics.V5Failed_Bind++;
        if( SS5Statistics.V5Current_Bind )
          SS5Statistics.V5Current_Bind--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V5UN:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V5Total_Udp++;        SS5Statistics.V5Normal_Udp++;
        if( SS5Statistics.V5Current_Udp )
          SS5Statistics.V5Current_Udp--;
        pthread_mutex_unlock( &CSMutex );    break;
      case V5UF:    pthread_mutex_lock( &CSMutex );    SS5Statistics.V5Total_Udp++;        SS5Statistics.V5Failed_Udp++;
        if( SS5Statistics.V5Current_Udp )
          SS5Statistics.V5Current_Udp--;
        pthread_mutex_unlock( &CSMutex );    break;
    }
  }

  return OK;
}
