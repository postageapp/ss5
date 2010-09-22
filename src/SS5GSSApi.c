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

#ifdef SS5_USE_GSSAPI

#include "SS5Main.h"
#include "SS5Mod_authentication.h"
#include "SS5GSSApi.h"



UINT S5GSSApiSetup( struct _SS5ClientInfo *ci )
{
  register UINT i;

  char logString[256];

  OM_uint32 majorS, minorS, tmp, retF;
  gss_OID ntype;

  gss_buffer_desc inbuffer, 
                  outbuffer, 
                  strbuffer;

  gss_name_t clientName, 
             serviceName;

  gss_cred_id_t cred   = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t context = GSS_C_NO_CONTEXT;

  unsigned char gssHeader[4];

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

 /* 
  * Get and import server name
  */
  if( SS5SocksOpt.GssPrincipal[0] == '\0' ) {
    if( gethostname(SS5SocksOpt.GssPrincipal, sizeof(SS5SocksOpt.GssPrincipal)) == -1 ) {
      snprintf(logString,256 - 1,"[%u] [DEBUG] GSS error getting hostname.", pid );
      LOGUPDATE()
      return ERR;
    }
  }

  strbuffer.value = SS5SocksOpt.GssPrincipal;
  strbuffer.length = strlen(SS5SocksOpt.GssPrincipal);
       
#ifdef SOLARIS
  majorS = gss_import_name(&minorS, &strbuffer, GSS_C_NT_HOSTBASED_SERVICE, &serviceName);
  /* TODO: majorS = gss_import_name(&minorS, &strbuffer, GSS_C_NULL_OID, &serviceName); */
#else
  majorS = gss_import_name(&minorS, &strbuffer, (gss_OID) gss_nt_service_name, &serviceName);
  /* TODO: majorS = gss_import_name(&minorS, &strbuffer, (gss_OID) GSS_C_NULL_OID, &serviceName); */
#endif

  if (majorS != GSS_S_COMPLETE) {
    S5LogGssSCode(pid, majorS, minorS );
    return ERR;
  }
       
 /* 
  * If DEBUG set, log GSS:  imported service name
  */
  if( DEBUG() ) {
    majorS = gss_display_name(&minorS, serviceName, &strbuffer, &ntype);

    if (majorS == GSS_S_COMPLETE) {
      snprintf(logString,256 - 1,"[%u] [DEBUG] GSS service name %s imported.", pid, (char *)strbuffer.value );
      LOGUPDATE()
    }
  }

 /* 
  * Acquire service credentials (no default login context)
  */
  majorS = gss_acquire_cred(&minorS, serviceName, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, 
                                  GSS_C_ACCEPT, &cred, NULL, NULL);

  if (majorS != GSS_S_COMPLETE) {
    S5LogGssSCode(pid, majorS, minorS );
    return ERR;
  }
  gss_release_name(&minorS, &serviceName);

  context = GSS_C_NO_CONTEXT;
  outbuffer.value = NULL;
  outbuffer.length = 0;

 /*
  * STEP 1:
  *        Setup GSS context
  *
  * ***********************************************************************************
  */

  do {
   /*
    * Get gss header (message type = 0x01) from gss client
    */
    if( recv(ci->Socket,gssHeader,sizeof(gssHeader),0) <= 0 ) {
      snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error receiving token header 0x01.", pid );
      LOGUPDATE()
      return ERR;
    }
    GET_GSSHEADER_LEN(gssHeader,inbuffer.length,GSS_OFFSET_HLEN)

   /*
    * Validate gss header
    */
    if( gssHeader[0] != (unsigned char)0x01 || gssHeader[1] != (unsigned char)0x01 ) {
      snprintf(logString,256 - 1,"[%u] [ERRO] GSS: malformed header or bad message type (should be 0x01).", pid );
      LOGUPDATE()
      return ERR;
    }
    if (inbuffer.length > (1 << 15) || inbuffer.length == 0) {
      snprintf(logString,256 - 1,"[%u] [ERRO] GSS: Incoming message malformed length.", pid );
      LOGUPDATE()
      return ERR;
    }

   /*
    * Receive message token from gss client
    */
    inbuffer.value = malloc(inbuffer.length);
    if (inbuffer.value == NULL && inbuffer.length != 0) {
      snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error allocating buffer %lu.", pid, (unsigned long)inbuffer.length );
      LOGUPDATE()
      return ERR;
    }

    if( recv(ci->Socket, inbuffer.value, inbuffer.length,0) <=0 ) {
      snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error receiving token data 0x01.", pid );
      LOGUPDATE()
      return ERR;
    }

   /*
    * Establishing a security context 
    */
    majorS = gss_accept_sec_context(&minorS, &context, cred, &inbuffer, GSS_C_NO_CHANNEL_BINDINGS, 
                                          &clientName, NULL, &outbuffer, &retF, NULL, NULL);

   /*
    * Send gss header (message type = 0x01) to gss client
    */
    if (outbuffer.length != 0) {

      gssHeader[0]= (u_char)0x01;
      gssHeader[1]= (u_char)0x01;
      SET_GSSHEADER_LEN(gssHeader,outbuffer.length,GSS_OFFSET_HLEN)

      if( send(ci->Socket,gssHeader,sizeof(gssHeader),SS5_SEND_OPT) == -1) {
        snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error sending token header 0x01.", pid );
        LOGUPDATE()
        gss_release_buffer(&tmp, &outbuffer);

        return ERR;
      }

     /*
      * Send message token to gss client
      */
      if( send(ci->Socket,outbuffer.value,outbuffer.length,SS5_SEND_OPT) == -1) {
        snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error sending token data 0x01.", pid );
        LOGUPDATE()
        gss_release_buffer(&tmp, &outbuffer);

        return ERR;
      }
    }
    gss_release_buffer(&tmp, &outbuffer);

    if (inbuffer.value) {
      free(inbuffer.value);
      inbuffer.value = NULL;
      inbuffer.length = 0;
    }

   /*
    * In case of an error in the context building, fail here
    */
    if (GSS_ERROR(majorS)) {
      gss_delete_sec_context(&tmp, &context, NULL);
      S5LogGssSCode(pid, majorS, minorS );

      return ERR;
    }

  } while(majorS & GSS_S_CONTINUE_NEEDED);
    
 /*
  * Check if context building is completed
  */
  if (majorS != GSS_S_COMPLETE) {
    S5LogGssSCode(pid, majorS, minorS );
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }
  
 /*
  * Set socks username to GSS client name
  */
  majorS = gss_display_name(&minorS, clientName, &strbuffer, &ntype);

  if (majorS != GSS_S_COMPLETE) {
    S5LogGssSCode(pid, majorS, minorS );
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }
  strncpy(ci->Username,(char *)strbuffer.value,strbuffer.length);
  gss_release_buffer(&minorS, &strbuffer);


 /*
  * STEP 2:
  *        Look for GSS encapsulation type
  *
  * ***********************************************************************************
  */

 /*
  * Get gss header (message type = 0x02) from gss client
  */
  if( recv(ci->Socket,gssHeader,sizeof(gssHeader),0) <= 0 ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error receiving token header 0x02.", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }
  GET_GSSHEADER_LEN(gssHeader,inbuffer.length,GSS_OFFSET_HLEN)

 /*
  * Validate gss header and message size
  */
  if( gssHeader[0] != (unsigned char)0x01 || gssHeader[1] != (unsigned char)0x02 ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: malformed header or bad message type (should be 0x02).", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }
  if (inbuffer.length > (1 << 15) || inbuffer.length == 0) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: Incoming message malformed length (token too big!).", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }

 /*
  * Get message 0x02 encapsulation type
  */
  if( recv(ci->Socket,&(ci->GssEnc),sizeof(inbuffer.length),0) <= 0 ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error receiving token data 0x02.", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }
 
 /*
  * Validate gss encapsulation
  */
  if( ci->GssEnc < 0 || ci->GssEnc > 2 ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS encapsulation requested invalid.", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }

 /* 
  * If DEBUG set, log GSS encampsulation required  
  */
  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBUG] GSS encapsulation requested %s.", pid, MSGGSS[ci->GssEnc] );
    LOGUPDATE()
  }
  
 /*
  * Send message 0x02 to confirm encapsulation type requested
  */
  gssHeader[0]= (u_char)0x01;
  gssHeader[1]= (u_char)0x02;
  SET_GSSHEADER_LEN(gssHeader,inbuffer.length,GSS_OFFSET_HLEN)


  if( send(ci->Socket,gssHeader,sizeof(gssHeader),SS5_SEND_OPT) == -1) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error sending token header 0x02.", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }
  if( send(ci->Socket,&(ci->GssEnc),1,SS5_SEND_OPT) == -1) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: error sending token data 0x02.", pid );
    LOGUPDATE()
    gss_delete_sec_context(&tmp, &context, NULL);

    return ERR;
  }

 /* 
  * Release GSS buffers 
  */
  gss_release_buffer(&tmp, &inbuffer);
  gss_release_name(&minorS, &clientName);

 /*
  * If encapsulation at least with INTEGRITY is required, save the GSS context
  * for next encode/decode operations.
  */
  if( GSSINTEGRITY() ) { 
    ci->GssContext=context; 
  }
  else 
    gss_delete_sec_context(&tmp, &context, NULL);

  return OK;
}



/*
 * GSS: ENCODING function
 *      
 *      used into socks5 module during <request parsing>, <connect serving>, <bind serving>
 * 
 */

UINT S5GSSApiEncode(gss_ctx_id_t ctx, UINT enc, unsigned char *inbuf, unsigned char **oubuf, int *len)
{
  register UINT i;

  OM_uint32 majorS, minorS, tmp;

  gss_buffer_desc inbuffer, outbuffer;

  int confReq;

  char logString[256];

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  inbuffer.value = inbuf;
  inbuffer.length = *len;
    
 /*
  * Encode data
  */
  majorS = gss_wrap(&minorS, ctx, (enc == GSS_ENC_INTEG)?0:1, GSS_C_QOP_DEFAULT, &inbuffer, &confReq, &outbuffer);
  if (majorS != GSS_S_COMPLETE ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS encoding token failed.", pid );
    LOGUPDATE()
    S5LogGssSCode(pid, majorS, minorS );

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }
  if( (*oubuf = malloc(outbuffer.length + 4)) == NULL ) {
    gss_release_buffer(&tmp, &outbuffer);
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS buffer allocating failed.", pid );
    LOGUPDATE()

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }

 /* 
  * If DEBUG set, log 
  */
  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBUG] GSS encoding %d buffer bytes to %d token bytes.", pid,*len,outbuffer.length );
    LOGUPDATE()
  }

 /*
  * Setup encapsulated message, header included
  */

  *(*(oubuf) + 0) = (unsigned )0x01;
  *(*(oubuf) + 1) = (unsigned short)0x03;
  SET_GSSHEADER_LEN((*(oubuf)),outbuffer.length,GSS_OFFSET_HLEN)

  memcpy(*(oubuf)+4, outbuffer.value, outbuffer.length);
  *len=(UINT)outbuffer.length + 4;

  gss_release_buffer(&tmp, &outbuffer);

  return OK;
}




UINT S5GSSApiDecode(gss_ctx_id_t ctx, UINT enc, unsigned char *inbuf, unsigned char **oubuf, int *len)
{
  register UINT i;
 
  char logString[256];

  OM_uint32 majorS, minorS, tmp;
  gss_buffer_desc inbuffer, outbuffer;

  int gssHeaderLen, confReq;

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

 /*
  * Validate gss header
  */
  GET_GSSHEADER_LEN(inbuf,gssHeaderLen,GSS_OFFSET_HLEN)
 
  if( inbuf[0] != (unsigned char)0x01 || inbuf[1] != (unsigned char)0x03 ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: malformed header or bad message type (should be 0x03).", pid );
    LOGUPDATE()

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }
  if (gssHeaderLen > (1 << 15) || gssHeaderLen == 0) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS: Incoming message malformed length (token too big!).", pid );
    LOGUPDATE()

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }
  inbuffer.value = inbuf + 4;
  inbuffer.length = *len - 4;

 /*
  * Decode data
  */
  majorS = gss_unwrap(&minorS, ctx, &inbuffer, &outbuffer, &confReq, NULL);

  if (majorS != GSS_S_COMPLETE ) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS decoding token failed.", pid );
    LOGUPDATE()
    S5LogGssSCode(pid, majorS, minorS );

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }

 /* 
  * If DEBUG set, log 
  */
  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBUG] GSS decoding %u token bytes to %u buffer bytes.", pid,inbuffer.length,outbuffer.length );
    LOGUPDATE()
  }

 /*
  * Check if encapsulation type is what it has been agreed with client
  */
  if (!confReq && enc == GSS_ENC_CONFI) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS encapsulation agreed (%d) differs from that received (1).", pid, enc );
    LOGUPDATE()
    gss_release_buffer(&tmp, &outbuffer);

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }
  else if (confReq && enc == GSS_ENC_INTEG) {
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS encapsulation agreed (%d) differs from that received (2).", pid, enc );
    LOGUPDATE()
    gss_release_buffer(&tmp, &outbuffer);

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }

  if( (*oubuf = malloc(outbuffer.length)) == NULL) {
    gss_release_buffer(&tmp, &outbuffer);
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS buffer allocating failed.", pid );
    LOGUPDATE()

    if( ctx != GSS_C_NO_CONTEXT )
      gss_delete_sec_context(&tmp, &ctx, NULL);

    return ERR;
  }
  memcpy(*oubuf, outbuffer.value, outbuffer.length); 
  *len = outbuffer.length;

  gss_release_buffer(&tmp, &outbuffer);

  return OK;
}




UINT S5LogGssSCode(pid_t p, int ma, int mi) {
  OM_uint32 majorS, minorS, msgCtx;

  gss_buffer_desc err;

  char logString[256];

  msgCtx = 0;
  do {
    majorS = gss_display_status(&minorS, ma, GSS_C_GSS_CODE, GSS_C_NULL_OID, &msgCtx, &err);
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS_MAJOR: %s.", p, (char *)err.value );
    LOGUPDATE()
    gss_release_buffer(&minorS, &err);
  } while( msgCtx );

  msgCtx = 0;
  do {
    majorS = gss_display_status(&minorS, mi, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msgCtx, &err);
    snprintf(logString,256 - 1,"[%u] [ERRO] GSS_MINOR: %s.", p, (char *)err.value );
    LOGUPDATE()
    gss_release_buffer(&minorS, &err);
  } while( msgCtx );

  return OK;
}

#endif
