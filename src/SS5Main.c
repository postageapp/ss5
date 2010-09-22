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
#include"SS5Core.h"
#include"SS5Modules.h"
#include"SS5Server.h"
#include"SS5Utils.h"
#include"SS5Thread.h"

UINT main(int argc, char **argv, char **envp) 
{
    struct sockaddr_in clientSsin;

    struct sigaction actionHungup;
    struct sigaction actionChild;
    struct sigaction actionPipe;

    register UINT idx1;
    register UINT idx2;

    UINT i,l;

    UINT totalChildren = 0;
    UINT newChildren   = 0;
    UINT forkChildren  = OK;
    UINT mode          = LOAD_CONFIG;

    int count;
    int status;
    int clientSocket;


    char socksAddr[16] = SS5_DEFAULT_ADDR;
    char socksPort[6]  = SS5_DEFAULT_PORT;
    char socksUser[32] = SS5_DEFAULT_USER;

    pid_t childPid;

    extern char S5PidFileName[MAXPPATHLEN];
    extern FILE *S5PidFile;
	
    /* 
     *    Initialize server static data to default values
     */
    S5SetStatic();

    /* 
     *    Get environment data config
     */
    for(count = 0; envp[count]; count++ )
      if( STREQ(envp[count],"SS5_SOCKS_USER=",sizeof("SS5_SOCKS_USER=") - 1) ) {
        strncpy(socksUser,(char *)getenv("SS5_SOCKS_USER"),sizeof(socksUser));
        fprintf(stderr,"[INFO] found environment SS5_SOCKS_USER:    %30s\n",socksUser);
      }
      else if( STREQ(envp[count],"SS5_SOCKS_PORT=",sizeof("SS5_SOCKS_PORT=") -1 ) ) {
        strncpy(socksPort,(char *)getenv("SS5_SOCKS_PORT"),sizeof(socksPort));
        fprintf(stderr,"[INFO] found environment SS5_SOCKS_PORT:    %30s\n",socksPort);
      }
      else if( STREQ(envp[count],"SS5_SOCKS_ADDR=",sizeof("SS5_SOCKS_ADDR=") - 1) ) {
        strncpy(socksAddr,(char *)getenv("SS5_SOCKS_ADDR"),sizeof(socksAddr));
        fprintf(stderr,"[INFO] found environment SS5_SOCKS_ADDR:    %30s\n",socksAddr);
      }
      else if( STREQ(envp[count],"SS5_PROPAGATE_KEY=",sizeof("SS5_PROPAGATE_KEY=") - 1) ) {
        strncpy(S5RepKey,(char *)getenv("SS5_PROPAGATE_KEY"),sizeof(S5RepKey));
        SS5SocksOpt.PropagateKey  = atol(S5RepKey);
        fprintf(stderr,"[INFO] found environment SS5_PROPAGATE_KEY\n");
      }
      else if( STREQ(envp[count],"SS5_ROLE_SLAVE=",sizeof("SS5_ROLE_SLAVE=") - 1) ) {
        SS5SocksOpt.Role  = SLAVE;
        fprintf(stderr,"[INFO] found environment SS5_ROLE_SLAVE\n");
      }
      else if( STREQ(envp[count],"SS5_CONFIG_FILE=",sizeof("SS5_CONFIG_FILE=") - 1) ) {
        strncpy(S5ConfigFile,(char *)getenv("SS5_CONFIG_FILE"),sizeof(S5ConfigFile));
        fprintf(stderr,"[INFO] found environment SS5_CONFIG_FILE:   %30s\n",S5ConfigFile);
      }
      else if( STREQ(envp[count],"SS5_LOG_FILE=",sizeof("SS5_LOG_FILE=") - 1) ) {
        strncpy(S5LoggingFile,(char *)getenv("SS5_LOG_FILE"),sizeof(S5LoggingFile));
        fprintf(stderr,"[INFO] found environment SS5_LOG_FILE:      %30s\n",S5LoggingFile);
      }
      else if( STREQ(envp[count],"SS5_PEERS_FILE=",sizeof("SS5_PEERS_FILE=") - 1) ) {
        strncpy(S5PeersFile,(char *)getenv("SS5_PEERS_FILE"),sizeof(S5PeersFile));
        fprintf(stderr,"[INFO] found environment SS5_PEERS_FILE:    %30s\n",S5PeersFile);
      }
      else if( STREQ(envp[count],"SS5_PASSWORD_FILE=",sizeof("SS5_PASSWORD_FILE=") - 1) ) {
        strncpy(S5PasswordFile,(char *)getenv("SS5_PASSWORD_FILE"),sizeof(S5PasswordFile));
        fprintf(stderr,"[INFO] found environment SS5_PASSWORD_FILE: %30s\n",S5PasswordFile);
      }
      else if( STREQ(envp[count],"SS5_LIB_PATH=",sizeof("SS5_LIB_PATH=") - 1) ) {
        strncpy(S5LibPath,(char *)getenv("SS5_LIB_PATH"),sizeof(S5LibPath));
        fprintf(stderr,"[INFO] found environment SS5_LIB_PATH:      %30s\n",S5LibPath);
      }

    STRSCAT(S5LibPath,"/ss5");

    /* 
     *    Parse command line parameters
     */
    for(count = 1 ;count < argc; count++) {
      if( argv[count][0] == '-' ) {
        switch( argv[count][1] ) {
          case 'c':   mode = PARSE_CONFIG;        break;    /*    Parse configuration file for syntax check    */
          case 'm':   SS5SocksOpt.Mute = OK;      break;    /*    Disable logging                              */
          case 's':   SS5SocksOpt.Syslog = OK;    break;    /*    Eneable logging to syslog instead of file    */
          case 'v':
            fprintf(stderr,"[INFO] %s\n",SS5_VERSION);
	    fprintf(stderr,"[INFO] %s\n",SS5_COPYRIGHT);

            S5ServerClose(EXIT);
	  break;
          case 't':
	    /*
	     *    Set threaded mode execution which use threads instead of processes
	     */
            if( SS5SocksOpt.PreforkProcesses > 1 )
              S5Usage();

            SS5SocksOpt.IsThreaded=OK;
	  break;
          case 'n':
	    /*
	     *    Set prefork number of processes to use for accept network connections
	     *
	     *    i.e. ss5 -n 10, prefork ten processes which accept network connections
	     */
            if (!argv[count+1] || THREADED() ) 
              S5Usage();
            else {
              if( strtol(argv[count+1], (char **)NULL, 10) > MAXPREFORKPROCS )
	        SS5SocksOpt.PreforkProcesses=MAXPREFORKPROCS;
	      else
	        SS5SocksOpt.PreforkProcesses = atoi(argv[count+1]);
                count++;
	    }
	  break;
          case 'u':
	    /*
	     *    Set username for ss5 execution
	     *
	     *    i.e. ss5 -u nobody, set nobody for ss5 execution
	     */
            if (!argv[count+1]) 
              S5Usage();
            else {
                strncpy(socksUser,argv[count+1],sizeof(socksUser));
                count++;
	    }
	  break;
          case 'b':
            if (!argv[count+1]) 
              S5Usage();
            else {
              /*
	       *    Set bind interface and port which ss5 listen for
	       *
	       *    i.e. ss5 -b 172.30.1.1:1082, listen on port 1082 on interface 172.30.1.1
	       *    i.e. ss5 -b 0.0.0.0:1082, listen on all interface on port 1082
	       */
	      for(idx1 = 0; idx1 < strlen(argv[count+1]) 
                            && (socksAddr[idx1] = argv[count+1][idx1]) != ':'
                            && argv[count+1][idx1]; idx1++);
	      socksAddr[idx1] = '\0';
	      idx1++;
	      for(idx2 = 0; idx2 < sizeof(socksPort) && (socksPort[idx2] = argv[count+1][idx1]); idx1++,idx2++)
                ;    /*    VOID    */
	      socksPort[idx2] = '\0';
	      count++;
	    }
	  break;
          case 'p':
            if (!argv[count+1]) 
              S5Usage();
            else {
              /*
               *  Set pid file
               */
              if((strlen(argv[count+1])+1)>MAXPPATHLEN) {
                fprintf(stderr,"Too long pid file path\n");
                S5ServerClose(EXIT);
				}
                strncpy(S5PidFileName,argv[count+1],sizeof(S5PidFileName));
		count++;
	    }
	  break;

          default:    S5Usage();    break;
	}
      }
      else
        S5Usage();
    }

    /*
     *    Load default modules: if you want to disable a module,
     *    rename it and ss5 will ignore it
     */
    S5LoadModules();

    pthread_mutex_init(&COMutex,NULL);

    /* 
     *    Start socks server in daemon mode
     */
    if( mode == LOAD_CONFIG ) {
      if( !S5MakeDaemon() )
        S5ServerClose(EXIT);
    }
    else {
      if( !S5LoadConfig(PARSE_CONFIG) )
        fprintf(stderr,"[ERRO] Error parsing configuration file (see ss5.log file for details).\n");
      else
        fprintf(stderr,"[INFO] Syntax OK\n");

      S5ServerClose(EXIT);
    }
    
    /* 
     *    Read and parse configuration file (/etc/opt/ss5/ss5.conf)
     */
    if( !S5LoadConfig(LOAD_CONFIG) ) {
        fprintf(stderr,"[ERRO] Error parsing configuration file (see ss5.log file for details). SS5 exiting...\n");
        S5ServerClose(EXIT);
    }

    /* 
     *    Write pid file
     */
    S5PidFile=fopen(S5PidFileName,"w+");

    if (S5PidFile == NULL) {
      fprintf(stderr,"Can't create pid file %s\n",S5PidFileName);
      S5ServerClose(EXIT);
    }
    if (fprintf(S5PidFile,"%d",(int)getpid())<=0) {
      fprintf(stderr,"Can't write to pid file %s\n",S5PidFileName);
      S5ServerClose(EXIT);
    }
    if (fclose(S5PidFile)!=0) {
      fprintf(stderr,"Can't close pid file %s\n",S5PidFileName);
      S5ServerClose(EXIT);
    }

    /* 
     *    Get information about network interfaces
     */
    if( !S5GetIf() )
      S5ServerClose(EXIT);

    /* 
     *    Set the effective user ID of the current process to nobody
     */
    if( !S5UIDSet(socksUser) ) {
      fprintf(stderr,"[ERRO] User %s not found.\n",socksUser);
      S5ServerClose(EXIT);
    }

    /* 
     *    Create socks server socket, bind socks server socket and listen for new connections
     */
    if( !S5ServerMake(socksAddr, atoi(socksPort)) )
      S5ServerClose(EXIT);

    /* 
     *    Ignore signal when child die
     */
    if( SS5SocksOpt.PreforkProcesses == 1 )  {
      actionChild.sa_flags   = SA_RESTART;
      actionChild.sa_handler = SIG_IGN;
      sigaction(SIGCHLD,&actionChild,NULL);
    }

    /* 
     *    Set HUNGUP handler to reload function
     *    and ignore SIGPIPE
     */
    actionHungup.sa_flags   = SA_RESTART;
    actionHungup.sa_handler = S5ReloadConfig;
    sigaction(SIGHUP,&actionHungup,NULL);

    actionPipe.sa_flags   = SA_RESTART;
    actionPipe.sa_handler = SIG_IGN;
    sigaction(SIGPIPE,&actionPipe,NULL);

    totalChildren = SS5SocksOpt.PreforkProcesses;

    for( ;; ) {
      /* 
       *    If set, use thread mode else use process mode
       */
      if( NOTTHREADED() ) {
        /* 
         *    Accept a new connection
         */ 
        if( SS5SocksOpt.PreforkProcesses == 1 ) {
          if( S5ServerAccept(&clientSsin, &clientSocket) ) {
            if( !(childPid = fork()) ) {
                S5Core(clientSocket);
            }
            else {
            /* 
             *    Here we are into father process
             *    where we free child process context 
             */
              S5ChildClose(CONTINUE,clientSocket,NULL);
            }
          }
        }
        else {
          /*
           *    Preforked mode: create new processes and each one
           *    can serves SS5SocksOpt.PreforkProcessLife requests
           */
          if( forkChildren ) { 
            forkChildren = ERR;
            for(idx1 = 0; idx1 < (SS5SocksOpt.PreforkProcesses - newChildren); idx1++) {
              if( !(childPid = fork()) ) {
               for(idx2 = 0; idx2 < SS5SocksOpt.PreforkProcessLife; idx2++) {
                  S5Core(0);
                }
                S5ChildClose(EXIT,0,NULL);
              }
              else {
              /* 
               *    Here we are into father process
               *    where we free child process context 
               */
              S5ChildClose(CONTINUE,0,NULL);
              }
            }
          }
          /*
           *    Wait for  and count any terminated child process: if n° childrens < 50% of preforked processes
           *    add new childrens
           */
          if( waitpid(-1,&status,0) == 0 ) {
    
          }
          else {
            /*
             *    Returns true if the child terminated normally or  because of a signal which was not caught
             *    and recalculate total childrens
             */
            if( WIFEXITED(status) || WIFSIGNALED(status) ) {
              totalChildren--;
              if( totalChildren <= (SS5SocksOpt.PreforkProcesses/2) ) {
                forkChildren  = OK;
                totalChildren = SS5SocksOpt.PreforkProcesses;
                newChildren   = (SS5SocksOpt.PreforkProcesses/2);
              }
            }
          }
        }
      }
      else {
        /*
         *    Launch ss5 in thread mode
         */
        S5MainThread(S5SocksSocket);
      }
    } 

    S5ServerClose(EXIT);

    return OK;
}

