/* Authors: Joshua Brindle  <jbrindle@tresys.com>
 *	    Jason Tang	    <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _SEMANAGE_HANDLE_H_
#define _SEMANAGE_HANDLE_H_

/* All accesses with semanage are through a "semanage_handle".  The
 * handle may ultimately reference local config files,
 * the binary policy file, a module store, or a policy management server. 
 */
struct semanage_handle;
typedef struct semanage_handle semanage_handle_t;

/* Create and return a semanage handle.
   The handle is initially in the disconnected state. */
semanage_handle_t *semanage_handle_create(void);

/* Deallocate all space associated with a semanage_handle_t, including
 * the pointer itself.	CAUTION: this function does not disconnect
 * from the backend; be sure that a semanage_disconnect() was
 * previously called if the handle was connected. */
void semanage_handle_destroy(semanage_handle_t *);

/* This is the type of connection to the store, for now only
 * direct is supported */
enum semanage_connect_type {
        SEMANAGE_CON_INVALID = 0, SEMANAGE_CON_DIRECT,
        SEMANAGE_CON_POLSERV_LOCAL, SEMANAGE_CON_POLSERV_REMOTE
};

/* This function allows you to specify the store to  connect to.
 * It must be called after semanage_handle_create but before 
 * semanage_connect. The argument should be the full path to the store.
 */
void semanage_select_store(semanage_handle_t *handle, char *path, 
			  enum semanage_connect_type storetype);

/* Just reload the policy */
int semanage_reload_policy(semanage_handle_t *handle);

/* set whether to reload the policy or not after a commit,
 * 1 for yes (default), 0 for no */
void semanage_set_reload(semanage_handle_t *handle, int do_reload);

/* set whether to rebuild the policy on commit, even if no
 * changes were performed.
 * 1 for yes, 0 for no (default) */
void semanage_set_rebuild(semanage_handle_t *handle, int do_rebuild);

/* create the store if it does not exist, this only has an effect on 
 * direct connections and must be called before semanage_connect 
 * 1 for yes, 0 for no (default) */
void semanage_set_create_store(semanage_handle_t *handle, int create_store);

/* Check whether policy is managed via libsemanage on this system.
 * Must be called prior to trying to connect.
 * Return 1 if policy is managed via libsemanage on this system,
 * 0 if policy is not managed, or -1 on error.
 */
int semanage_is_managed(semanage_handle_t *);

/* "Connect" to a manager based on the configuration and 
 * associate the provided handle with the connection.
 * If the connect fails then this function returns a negative value, 
 * else it returns zero.
 */
int semanage_connect(semanage_handle_t *);

/* Disconnect from the manager given by the handle.  If already
 * disconnected then this function does nothing.  Return 0 if
 * disconnected properly or already disconnected, negative value on
 * error. */
int semanage_disconnect(semanage_handle_t *);

/* Attempt to obtain a transaction lock on the manager.	 If another
 * process has the lock then this function may block, depending upon
 * the timeout value in the handle.
 *
 * Note that if the semanage_handle has not yet obtained a transaction
 * lock whenever a writer function is called, there will be an
 * implicit call to this function. */
int semanage_begin_transaction(semanage_handle_t *);

/* Attempt to commit all changes since this transaction began.	If the
 * commit is successful then increment the "policy sequence number"
 * and then release the transaction lock.  Return that policy number
 * afterwards, or -1 on error.
 */
int semanage_commit(semanage_handle_t *);

#define SEMANAGE_CAN_READ 1
#define SEMANAGE_CAN_WRITE 2
/* returns SEMANAGE_CAN_READ or SEMANAGE_CAN_WRITE if the store is readable
 * or writable, respectively. <0 if an error occured */ 
int semanage_access_check(semanage_handle_t *sh);

/* returns 0 if not connected, 1 if connected */
int semanage_is_connected(semanage_handle_t *sh);

/* META NOTES
 *
 * For all functions a non-negative number indicates success. For some
 * functions a >=0 returned value is the "policy sequence number".  This
 * number keeps tracks of policy revisions and is used to detect if
 * one semanage client has committed policy changes while another is
 * still connected.
 */

#endif
