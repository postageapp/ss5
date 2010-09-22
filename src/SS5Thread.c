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
#include "SS5Core.h"
#include "SS5Thread.h"
#include "SS5Server.h"
#include "SS5Mod_authentication.h"
#include "SS5Mod_authorization.h"
#include "SS5Mod_statistics.h"
#include "SS5Mod_balance.h"


UINT S5MainThread( int socksSocket )
{
  struct sockaddr_in clientSsin;

  int clientSocket;

  sigset_t newMask;
  sigset_t oldMask;

  IFEPOLL( struct epoll_event ev; )
  IFEPOLL( struct epoll_event *events; )
  IFEPOLL( int nfds; )
  IFEPOLL( int kdpfd; )
  IFEPOLL( int maxEvents = 5; )

  IFSELECT( struct timeval tv; )
  IFSELECT( int fd; )
  IFSELECT( fd_set array; )

  IFEPOLL( if( (events = calloc(maxEvents, sizeof(struct epoll_event))) == NULL ) )
  IFEPOLL(   return ERR; )

  IFEPOLL( kdpfd=epoll_create(maxEvents); )

  IFEPOLL( ev.events = EPOLLIN; )
  IFEPOLL( ev.data.fd = socksSocket; )
  IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, socksSocket, &ev); )

  pthread_mutex_init(&CTMutex,NULL);
  pthread_mutex_init(&PAMMutex,NULL);
  pthread_mutex_init(&BTMutex,NULL);
  pthread_mutex_init(&ACMutex,NULL);

  for( ;; ) {
    IFSELECT( FD_ZERO(&array); )
    IFSELECT( FD_SET(socksSocket,&array); )
    /*
     *    How long we have to wait for a new query? In future we'll use this information
     *    for maintaining a pool of threads
     */
    IFSELECT( tv.tv_sec=SS5SocksOpt.AcceptTimeout; )
    IFSELECT( tv.tv_usec=0; )

    sigemptyset(&newMask);
    sigaddset(&newMask,SIGPIPE);
    sigaddset(&newMask,SIGALRM);
    sigprocmask(SIG_BLOCK,&newMask,&oldMask);

    IFEPOLL( nfds = epoll_wait(kdpfd, events, maxEvents, SS5SocksOpt.AcceptTimeout*1000); )
    IFSELECT( fd=select(socksSocket+1,&array,NULL,NULL,&tv); )
    
    IFEPOLL( if( nfds ) { )
    IFSELECT( if( fd ) { )
      pthread_attr_t s5thread_attribute;
      pthread_t s5thread;

      S5ServerAccept(&clientSsin,&clientSocket);
      /* 
       *    Initializes thread attributes: stack, scope, detach state and fills it with specific values
       */
      pthread_attr_init(&s5thread_attribute);
      pthread_attr_setstacksize(&s5thread_attribute, 131072);
      pthread_attr_setscope(&s5thread_attribute, PTHREAD_SCOPE_SYSTEM);
      pthread_attr_setdetachstate(&s5thread_attribute, PTHREAD_CREATE_DETACHED);

      if( pthread_create(&s5thread,&s5thread_attribute,(void *)S5Core,(void *)clientSocket) < 0 ) {
        SS5Modules.mod_logging.Logging("[ERRO] Error creating thread.");
      }
      else {
	pthread_detach(s5thread);
      }
    }
  }
  return OK;
}
