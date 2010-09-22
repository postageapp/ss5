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
#include"SS5Server.h"

#ifdef SOLARIS
  #include <link.h>
#endif

#include<dlfcn.h>

UINT S5LoadModules( void ) 
{
  UINT (*InitModule)(struct _module *m);
  UINT i,l;

  const char *error;
  char libpath[128];

  /*
   *    Load SS5 SOCKS4 module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_socks4.so");

  SS5Modules.mod_socks4_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_socks4_handle) {
    fprintf(stderr,"[WARN] Modules mod_socks4.so not found in %s. Module not loaded.\n",S5LibPath);
    SS5Modules.mod_socks4_loaded=ERR;
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_socks4_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_socks4.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 

    (*InitModule)(&SS5Modules.mod_socks4);
    SS5Modules.mod_socks4_loaded=OK;
  } 

  /*
   *    Load SS5 SOCKS5 module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_socks5.so");

  SS5Modules.mod_socks5_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_socks5_handle) {
    fprintf(stderr,"[ERRO] Modules mod_socks5.so not found in %s. SS5 exiting...\n",S5LibPath);
    S5ServerClose(EXIT);
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_socks5_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_socks5.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_socks5);
    SS5Modules.mod_socks5_loaded=OK;
  }

  /*
   *    Load SS5 AUTHENTICATION module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_authentication.so");

  SS5Modules.mod_authentication_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_authentication_handle) {
    fprintf(stderr,"[ERRO] Modules mod_authentication.so not found in %s. SS5 exiting...\n",S5LibPath);
    S5ServerClose(EXIT);
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_authentication_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_authentication.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_authentication);
    SS5Modules.mod_authentication_loaded=OK;
  }

  /*
   *    Load SS5 AUTHORIZATION module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_authorization.so");

  SS5Modules.mod_authorization_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_authorization_handle) {
    fprintf(stderr,"[ERRO] Modules mod_authorization.so not found in %s. SS5 exiting...\n",S5LibPath);
    S5ServerClose(EXIT);
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_authorization_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_authorization.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_authorization);
    SS5Modules.mod_authorization_loaded=OK;
  } 

  /*
   *    Load SS5 PROXY module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_proxy.so");

  SS5Modules.mod_proxy_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_proxy_handle) {
    fprintf(stderr,"[ERRO] Modules mod_proxy.so not found in %s. SS5 exiting...\n",S5LibPath);
    S5ServerClose(EXIT);
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_proxy_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_proxy.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_proxy);
    SS5Modules.mod_proxy_loaded=OK;
  } 
 
  /*
   *    Load SS5 BALANCING module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_balance.so");

  SS5Modules.mod_balancing_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_balancing_handle) {
    fprintf(stderr,"[WARN] Modules mod_balance.so not found in %s. Module not loaded.\n",S5LibPath);
    SS5Modules.mod_balancing_loaded=ERR;
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_balancing_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_balance.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_balancing);
    SS5Modules.mod_balancing_loaded=OK;
  } 
 
  /*
   *    Load SS5 LOG module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_log.so");

  SS5Modules.mod_proxy_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_proxy_handle) {
    fprintf(stderr,"[ERRO] Modules mod_log.so not found in %s. SS5 exiting...\n",S5LibPath);
    S5ServerClose(EXIT);
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_proxy_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_log.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_logging);
    SS5Modules.mod_logging_loaded=OK;
  }

  /*
   *    Load SS5 FILTERING module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_filter.so");

  SS5Modules.mod_filter_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_filter_handle) {
    fprintf(stderr,"[WARN] Modules mod_filter.so not found in %s. Module not loaded.\n",S5LibPath);
    SS5Modules.mod_filter_loaded=ERR;
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_filter_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_filter.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_filter);
    SS5Modules.mod_filter_loaded=OK;
  } 
 
  /*
   *    Load SS5 STATISTICS module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_statistics.so");

  SS5Modules.mod_statistics_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_statistics_handle) {
    fprintf(stderr,"[WARN] Modules mod_statistics.so not found in %s. Module not loaded.\n",S5LibPath);
    SS5Modules.mod_statistics_loaded=ERR;
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_statistics_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_statistics.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_statistics);
    SS5Modules.mod_statistics_loaded=OK;
  } 

  /*
   *    Load SS5 BANDWIDTH module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_bandwidth.so");

  SS5Modules.mod_bandwidth_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_bandwidth_handle) {
    fprintf(stderr,"[WARN] Modules mod_bandwidth.so not found in %s. Module not loaded.\n",S5LibPath);
    SS5Modules.mod_bandwidth_loaded=ERR;
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_bandwidth_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_bandwidth.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    } 
    (*InitModule)(&SS5Modules.mod_bandwidth);
    SS5Modules.mod_bandwidth_loaded=OK;
  } 

  /*
   *    Load SS5 DUMP module
   */
  strncpy(libpath,S5LibPath,sizeof(S5LibPath));
  STRSCAT(libpath,"/mod_dump.so");

  SS5Modules.mod_dump_handle = dlopen(libpath,RTLD_LAZY);
  if( !SS5Modules.mod_dump_handle) {
    fprintf(stderr,"[WARN] Modules mod_dump.so not found in %s. Module not loaded.\n",S5LibPath);
    SS5Modules.mod_dump_loaded=ERR;
  }
  else {
    dlerror();    /* Clear any existing error */

   /*
    *    Initialize module    
    */
    *(void **) (&InitModule) = dlsym(SS5Modules.mod_dump_handle,"InitModule");
    if((error = dlerror()) != NULL) {
      fprintf(stderr, "[ERRO] Error initializing module mod_dump.so. SS5 exiting...\n");
      S5ServerClose(EXIT);
    }
    (*InitModule)(&SS5Modules.mod_dump);
    SS5Modules.mod_dump_loaded=OK;
  }

  return OK; 
}


UINT S5UnLoadModules( void ) 
{
  dlclose(SS5Modules.mod_socks5_handle);
  
  return OK;
}
