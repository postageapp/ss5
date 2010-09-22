/* Socks Server 5
 * Copyright (C) 2003 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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

#ifndef SS5PAM_H
#define SS5PAM_H 1

#ifdef LINUX
  #include <security/pam_misc.h>
#endif

#include <security/pam_appl.h>

/*
 *  *  * SS5: PAM buffers
 *   *   */
struct _S5PamData {
  const char *user;
  const char *password;
};


UINT
  S5PamCheck(		struct _SS5ClientInfo *ci
);

/*static int
  S5PAMConversation(	int nmsg,
			const struct pam_message **pam_msg,
			struct pam_response **resp,
			void *s5data
);*/

#endif
