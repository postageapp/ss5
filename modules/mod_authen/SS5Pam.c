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
#include "SS5Pam.h"
#include "SS5Mod_log.h"

static int
  S5PAMConversation(    int nmsg,
                        const struct pam_message **pam_msg,
                        struct pam_response **resp,
                        void *s5data
);


UINT S5PamCheck(struct _SS5ClientInfo *ci)
{
  int pamError;

  char logString[256];

  pam_handle_t *pamHandle = NULL;

  struct _S5PamData pw;
  
  pid_t pid;


  /*
   *    Set S5PAMConversation like data exchange function from Application to PAM;
   *    In this case, we pass username & password.
   */
  static struct pam_conv s5conv = {
    &S5PAMConversation,
    NULL
  };

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   *    Initialize PAM with "ss5" service
   */ 
  if( VERBOSE() ) {
    snprintf(logString,256 - 1,"[%u] [VERB] Starting PAM.",pid);
    SS5Modules.mod_logging.Logging(logString);
  }

  if( THREADED() )
    LOCKMUTEXPAM();
  if( (pamError = pam_start("ss5", ci->Username, &s5conv, &pamHandle)) != PAM_SUCCESS ) {
    ERRNOPAM(pid,pamHandle,pamError)

    if( THREADED() )
      UNLOCKMUTEXPAM();
    return ERR;
  }
      
  pw.user     = (const char *)ci->Username;
  pw.password = (const char *)ci->Password;
  s5conv.appdata_ptr = (char *)&pw;

  /*
   *    Set PAM item (username and password)
   */ 
  if( VERBOSE() ) {
    snprintf(logString,256 - 1,"[%u] [VERB] Setting PAM item.",pid);
    SS5Modules.mod_logging.Logging(logString);
  }
  if( (pamError=pam_set_item(pamHandle,PAM_CONV,&s5conv)) != PAM_SUCCESS ) {
    ERRNOPAM(pid,pamHandle,pamError)

    if (pam_end(pamHandle,pamError) != PAM_SUCCESS) {    
      ERRNOPAM(pid,pamHandle,pamError)

      pamHandle = NULL;

      if( THREADED() )
        UNLOCKMUTEXPAM();
      return ERR;
    }

    pamHandle = NULL;
    if( THREADED() )
      UNLOCKMUTEXPAM();
    return ERR;
  }

  /*
   *    PAM authentication
   */
  if( VERBOSE() ) {
    snprintf(logString,256 - 1,"[%u] [VERB] Authenticating PAM.",pid);
    SS5Modules.mod_logging.Logging(logString);
  }
  pamError = pam_authenticate(pamHandle, 0);

  if (pamError != PAM_SUCCESS) {
    ERRNOPAM(pid,pamHandle,pamError)

    if (pam_end(pamHandle,pamError) != PAM_SUCCESS) {    
      ERRNOPAM(pid,pamHandle,pamError)

      pamHandle = NULL;

      if( THREADED() )
        UNLOCKMUTEXPAM();
      return ERR;
    }

    pamHandle = NULL;
    if( THREADED() )
      UNLOCKMUTEXPAM();
    return ERR;
  }

  /*
   *    PAM handle closing
   */
  if( VERBOSE() ) {
    snprintf(logString,256 - 1,"[%u] [VERB] Closing PAM.",pid);
    SS5Modules.mod_logging.Logging(logString);
  }
  if (pam_end(pamHandle,pamError) != PAM_SUCCESS) {    
    ERRNOPAM(pid,pamHandle,pamError)

    pamHandle = NULL;

    if( THREADED() )
      UNLOCKMUTEXPAM();
    return ERR;
  }

  if( pamError == PAM_SUCCESS )  {
    if( THREADED() )
      UNLOCKMUTEXPAM();
    return OK;
  }

  if( THREADED() )
    UNLOCKMUTEXPAM();
  return ERR;
}

static int S5PAMConversation(int nmsg, const struct pam_message **pam_msg, struct pam_response **resp, void *s5data)
{
  int idx;
  struct _S5PamData *pw = (struct _S5PamData *)s5data;
  struct pam_response *reply = NULL;

  if( reply )
    realloc(reply, sizeof(struct pam_response));
  else
    reply = calloc(nmsg, sizeof(struct pam_response));

  if( reply == NULL )
    return PAM_CONV_ERR;

  for (idx = 0; idx < nmsg; idx++) {
    switch( pam_msg[idx]->msg_style ) {
      case PAM_PROMPT_ECHO_ON:
        free(reply);
        return PAM_CONV_ERR;
      break;
      case PAM_PROMPT_ECHO_OFF:
        reply[idx].resp_retcode = PAM_SUCCESS;
        if( s5data )
          reply[idx].resp = strdup(pw->password);
        else
          reply[idx].resp = strdup("");
      break;
      case PAM_ERROR_MSG:
      default:
        free(reply);
        return PAM_CONV_ERR;
    }
  }
  *resp = reply;
  return PAM_SUCCESS;
}
