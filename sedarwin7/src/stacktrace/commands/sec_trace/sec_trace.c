/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * Copyright (c) 2004 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 *
 * XXXRW: Some code in this file appears to be under APSLv1; can we find an
 * APSLv2 source instead?
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "stacktrace_syscalls.h"

/*
 * User command that captures, formats, and prints a security stack trace
 * created by the mac_stacktrace security policy module.
 */
char *funcname[] = {
	"destroy",
	"init",
	"init_bsd",
	"init_cred_label",
	"init_lctx_label",
	"init_devfsdirent_label",
	"init_mbuf_failed_label",
	"init_mbuf_socket_label",
	"init_mount_label",
	"init_mount_fs_label",
	"init_port_label",
	"init_posix_sem_label",
	"init_posix_shm_label",
	"init_proc_label",
	"init_socket_label",
	"init_socket_peer_label",
	"init_sysv_sem_label",
	"init_sysv_shm_label",
	"init_task_label",
	"init_tcp_label",
	"init_mbuf_unknown_source_label",
	"init_vnode_label",
	"destroy_cred_label",
	"destroy_lctx_label",
	"destroy_devfsdirent_label",
	"destroy_mbuf_socket_label",
	"destroy_mount_label",
	"destroy_mount_fs_label",
	"destroy_port_label",
	"destroy_posix_sem_label",
	"destroy_posix_shm_label",
	"destroy_proc_label",
	"destroy_socket_label",
	"destroy_socket_peer_label",
	"destroy_sysv_sem_label",
	"destroy_sysv_shm_label",
	"destroy_task_label",
	"destroy_vnode_label",
	"cleanup_sysv_sem_label",
	"cleanup_sysv_shm_label",
	"copy_cred_to_task",
	"update_port_from_cred_label",
	"copy_vnode_label",
	"copy_devfs_label",
	"copy_mbuf_socket_label",
	"copy_port_label",
	"externalize_cred_label",
	"externalize_cred_audit_label",
	"externalize_lctx_label",
	"externalize_vnode_label",
	"externalize_vnode_audit_label",
	"internalize_cred_label",
	"internalize_lctx_label",
	"internalize_vnode_label",
	"associate_vnode_devfs",
	"associate_vnode_extattr",
	"associate_vnode_singlelabel",
	"create_devfs_device",
	"create_devfs_directory",
	"create_devfs_symlink",
	"create_vnode_extattr",
	"create_mount",
	"relabel_vnode",
	"setlabel_vnode_extattr",
	"update_devfsdirent",
	"copy_socket_label",
	"create_socket",
	"create_socket_from_socket",
	"create_mbuf_from_socket",
	"externalize_socket_label",
	"externalize_socket_peer_label",
	"internalize_socket_label",
	"relabel_socket",
	"set_socket_peer_from_socket",
	"set_socket_peer_from_mbuf",
	"create_port",
	"create_kernel_port",
	"update_port_kobject",
	"create_posix_sem",
	"create_posix_shm",
	"create_sysv_sem",
	"create_sysv_shm",
	"create_cred",
	"create_task",
	"create_kernel_task",
	"execve_transition",
	"execve_will_transition",
	"create_proc0",
	"create_proc1",
	"relabel_cred",
	"request_object_label",
	"proc_create_lctx",
	"proc_join_lctx",
	"proc_leave_lctx",
	"relabel_lctx",
	"check_service_access",
	"check_cred_relabel",
	"check_lctx_relabel",
	"check_port_relabel",
	"check_port_send",
	"check_port_make_send",
	"check_port_copy_send",
	"check_port_hold_send",
	"check_port_hold_receive",
	"check_port_move_receive",
	"check_cred_visible",
	"check_fcntl",
	"check_get_fd",
	"check_ioctl",
	"check_ipc_method",
	"check_posix_sem_create",
	"check_posix_sem_open",
	"check_posix_sem_post",
	"check_posix_sem_unlink",
	"check_posix_sem_wait",
	"check_posix_shm_create",
	"check_posix_shm_open",
	"check_posix_shm_mmap",
	"check_posix_shm_stat",
	"check_posix_shm_truncate",
	"check_posix_shm_unlink",
	"check_sysv_semctl",
	"check_sysv_semget",
	"check_sysv_semop",
	"check_sysv_shmat",
	"check_sysv_shmctl",
	"check_sysv_shmdt",
	"check_sysv_shmget",
	"check_mount_stat",
	"check_proc_debug",
	"check_proc_sched",
	"check_proc_signal",
	"check_proc_wait",
	"check_set_fd",
	"check_socket_accept",
	"check_socket_bind",
	"check_socket_connect",
	"check_socket_deliver",
	"check_socket_listen",
	"check_socket_poll",
	"check_socket_receive",
	"check_socket_relabel",
	"check_socket_select",
	"check_socket_send",
	"check_socket_stat",
	"check_system_acct",
	"check_system_nfsd",
	"check_system_reboot",
	"check_system_settime",
	"check_system_swapon",
	"check_system_swapoff",
	"check_system_sysctl",
	"check_vnode_access",
	"check_vnode_chdir",
	"check_vnode_chroot",
	"check_vnode_create",
	"check_vnode_delete",
	"check_vnode_deleteextattr",
	"check_vnode_exchangedata",
	"check_vnode_exec",
	"check_vnode_getattrlist",
	"check_vnode_getextattr",
	"check_vnode_link",
	"check_vnode_listextattr",
	"check_vnode_lookup",
	"check_vnode_mmap",
	"check_vnode_mmap_downgrade",
	"check_vnode_mprotect",
	"check_vnode_open",
	"check_vnode_poll",
	"check_vnode_read",
	"check_vnode_readdir",
	"check_vnode_readlink",
	"check_vnode_relabel",
	"check_vnode_rename_from",
	"check_vnode_rename_to",
	"check_vnode_revoke",
	"check_vnode_select",
	"check_vnode_setattrlist",
	"check_vnode_setextattr",
	"check_vnode_setflags",
	"check_vnode_setmode",
	"check_vnode_setowner",
	"check_vnode_setutimes",
	"check_vnode_stat",
	"check_vnode_write",
	"check_system_audit",
	"check_system_auditon",
	"check_system_auditctl",
	"check_proc_getauid",
	"check_proc_getlcid",
	"check_proc_setauid",
	"check_proc_setlcid",
	"check_proc_getaudit",
	"check_proc_setaudit",
	"audit_preselect",
	"audit_postselect"
};

/*
 * Code cloned from latency.c.
 */
char	*pc_to_string();
char	 pcstring[128];
void	 do_kernel_nm();
char	*kernelpath = "/mach_kernel";
typedef struct {
	u_long	 k_sym_addr;		/* Kernel symbol address from nm. */
	u_int	 k_sym_len;		/* Length of kernel symbol string. */
	char	*k_sym_name;		/* Kernel symbol string from nm. */
} kern_sym_t;
kern_sym_t	*kern_sym_tbl;		/* Pointer to the nm table. */
int		 kern_sym_count;	/* Number of entries in nm table. */

/*
 * Action functions executed to print the trace.
 */
int
printhead(char *s)
{

	printf("%s\n", s);
	return (0);
}

int
printline(int sl, int cl, char *s)
{

	printf("  %#010x %#010x %s\n", sl, cl, s);
	return (0);
}

int
main(int argc, char **argv)
{
	struct stacktrace_buf_head *sbhp;
	struct tracehead *tracep;
	int (*headf)(char *);
	int (*linef)(int, int, char *);
	char *storagep;

	storagep = malloc(RBSIZE);
	if (storagep == NULL) {
		printf("%s: error from malloc\n", argv[0]);
		exit(1);
	}

	headf = printhead;
	linef = printline;
	if (argc > 3) {
		printf("usage:  %s [path] [kernel]\n", argv[0]);
		exit(1);
	}

	if (argc >= 2) {
		/*
		 * Read in a trace buffer saved by save_trace.  If specified,
		 * use an alternative symtb rather than the live kernel.
		 *
		 * TODO: Read the file header to find out the size, then
		 * mmap() it.
		 */
		FILE *fp;

		fp = fopen(argv[1], "r");
		if (fp == NULL) {
			fprintf(stderr, "%s: error from open %s\n", argv[0],
			    argv[1]);
			exit(1);
		}
		fread(storagep, RBSIZE, 1, fp);
		fclose(fp);

		if (argc == 3)
			kernelpath = argv[2];
	} else {
		/*
		 * Read data from hardcore.
		 *
		 * TODO: Find out size from syscall.
		 */
		struct stacktrace_user_args stu;
		int error;

		stu.userbuffp = storagep;
		stu.bufmaxsize = RBSIZE;
		stu.version = STACKTRACE_INTERFACE_VERSION;
		error = mac_syscall("stacktrace", STACKTRACECALL_GETBUF, &stu);
		if (error != 0) {
			fprintf(stderr, "%s: error from syscall %d\n",
			    argv[0], error);
			exit(1);
		}
	}

	sbhp = (struct stacktrace_buf_head *)storagep;
	if (sbhp->version != STACKTRACE_INTERFACE_VERSION) {
		fprintf(stderr, "%s: this program is for version %d data, "
		    "input is version %d\n", argv[0],
		    STACKTRACE_INTERFACE_VERSION, sbhp->version);
		exit(1);
	}

	/*
	 * Get the kernel symbol table into a malloc()'d structure.
	 */
	do_kernel_nm();

	/*
	 * TODO: Print the time of last call and the time of the last reset.
	 */
	printf("%ld calls %ld wraps, max depth %d\n", sbhp->ncalls,
	    sbhp->bufwraps, sbhp->maxdepth);

	tracep = (struct tracehead *)&(sbhp->next);
	while ((tracep != NULL) &&
	    (((char *)tracep+sizeof(struct stacktrace_buf_head)) < (storagep+RBSIZE))
	    && (tracep->ntracelines > 0)) {
		struct traceline *tlp;
		short nlines;
		char *s;
		int i;

		nlines = tracep->ntracelines;
		(*headf)(funcname[tracep->function]);
		tlp = (struct traceline *)&(tracep->tracelines);
		for (i=0; i<nlines; i++) {
			s = pc_to_string(tlp->codeloc);
			(*linef)(tlp->stackloc, tlp->codeloc, s);
			tlp = (struct traceline *)&(tlp->nexttraceline);
		}
		tracep = (struct tracehead *)tlp;
	}

	exit(0);
}

// ================================================================
// code cloned from latency.c
// ================================================================

void
do_kernel_nm(void)
{
  int i, len;
  FILE *fp = (FILE *)0;
  char tmp_nm_file[128];
  char tmpstr[1024], c;
  int inchr;

  memset(tmp_nm_file, 0, 128);
  memset(tmpstr, 0, 1024);

  /* Build the temporary nm file path */
  sprintf(tmp_nm_file, "/tmp/knm.out.%d", getpid());

  /* Build the nm command and create a tmp file with the output*/
  sprintf (tmpstr, "/usr/bin/nm -f -n -s __TEXT __text %s > %s",
	   kernelpath, tmp_nm_file);
  system(tmpstr);

  /* Parse the output from the nm command */
  if ((fp=fopen(tmp_nm_file, "r")) == (FILE *)0)
    {
      /* Hmmm, let's not treat this as fatal */
      fprintf(stderr, "Failed to open nm symbol file [%s]\n", tmp_nm_file);
      return;
    }

  /* Count the number of symbols in the nm symbol table */
  kern_sym_count=0;
  while ( (inchr = getc(fp)) != -1)
    {
      if (inchr == '\n')
	kern_sym_count++;
    }

  rewind(fp);

  /* Malloc the space for symbol table */
  if (kern_sym_count > 0)
    {
       kern_sym_tbl = (kern_sym_t *)malloc(kern_sym_count * sizeof (kern_sym_t));
       if (!kern_sym_tbl)
	 {
	   /* Hmmm, lets not treat this as fatal */
	   fprintf(stderr, "Can't allocate memory for kernel symbol table\n");
	 }
       else
	 memset(kern_sym_tbl, 0, (kern_sym_count * sizeof(kern_sym_t)));
    }
  else
    {
      /* Hmmm, lets not treat this as fatal */
      fprintf(stderr, "No kernel symbol table \n");
    }

  for (i=0; i<kern_sym_count; i++)
    {
      memset(tmpstr, 0, 1024);
      if (fscanf(fp, "%lx %c %s", &kern_sym_tbl[i].k_sym_addr, &c, tmpstr) != 3)
	break;
      else
	{
	  len = strlen(tmpstr);
	  kern_sym_tbl[i].k_sym_name = (char *)malloc(len + 1);

	  if (kern_sym_tbl[i].k_sym_name == (char *)0)
	    {
	      fprintf(stderr, "Can't allocate memory for symbol name [%s]\n", tmpstr);
	      kern_sym_tbl[i].k_sym_name = (char *)0;
	      len = 0;
	    }
	  else
	    strcpy(kern_sym_tbl[i].k_sym_name, tmpstr);

	  kern_sym_tbl[i].k_sym_len = len;
	}
    } /* end for */

  if (i != kern_sym_count)
    {
      /* Hmmm, didn't build up entire table from nm */
      /* scrap the entire thing */
      if (kern_sym_tbl)
	free (kern_sym_tbl);
      kern_sym_tbl = (kern_sym_t *)0;
      kern_sym_count = 0;
    }

  fclose(fp);

  /* Remove the temporary nm file */
  unlink(tmp_nm_file);

#if 0
  /* Dump the kernel symbol table */
  for (i=0; i < kern_sym_count; i++)
    {
      if (kern_sym_tbl[i].k_sym_name)
	  printf ("[%d] 0x%x    %s\n", i,
		  kern_sym_tbl[i].k_sym_addr, kern_sym_tbl[i].k_sym_name);
      else
	  printf ("[%d] 0x%x    %s\n", i,
		  kern_sym_tbl[i].k_sym_addr, "No symbol name");
    }
#endif
} // do_kernel_nm


/* Convert a PC value to a string */
/* uses global kern_sym_tbl, kern_sym_count */
/* sets global pcstring */
#define TOOBIG 100000

char *
pc_to_string(unsigned int pc)
{
  int ret;
  int len;

  int binary_search();

  ret=0;
  ret = binary_search(kern_sym_tbl, 0, kern_sym_count-1, pc);
  int offset = pc - kern_sym_tbl[ret].k_sym_addr;

  if ((ret == -1) ||
      (kern_sym_tbl[ret].k_sym_name == (char *)0) ||
      (offset < 0) ||
      (offset > TOOBIG))
    {
      pcstring[0] = 0;
      return(pcstring);
    }
  else
    {
      len = kern_sym_tbl[ret].k_sym_len;

      memcpy(pcstring, kern_sym_tbl[ret].k_sym_name, len);
      sprintf(&pcstring[len], "+%d", offset);

      return (pcstring);
    }
} // pc_to_string


/* Return -1 if not found, else return index */
int binary_search(list, low, high, addr)
kern_sym_t *list;
int low, high;
unsigned int  addr;
{
  int mid;

  mid = (low + high) / 2;

  if (low > high)
    return (-1);   /* failed */
  else if (low + 1 == high)
    {
      if (list[low].k_sym_addr <= addr &&
	   addr < list[high].k_sym_addr)
	{
	  /* We have a range match */
	  return(low);
	}
      else if (list[high].k_sym_addr <= addr)
	{
	  return(high);
	}
      else
	return(-1);   /* Failed */
    }
  else if (addr < list[mid].k_sym_addr)
    {
      return(binary_search (list, low, mid, addr));
    }
  else
    {
      return(binary_search (list, mid, high, addr));
    }
} // binary_search
