
/*
 * Author:  Stephen Smalley (NAI Labs), <ssmalley@nai.com>
 */

/* FLASK */

/* 
 * Global definitions that are included at the beginning
 * of every file using the -include directive.
 *
 * These definitions are used to permit the same
 * source code to be used to build both the security
 * server component of the kernel and the checkpolicy
 * program.
 */

#ifndef __SS_GLOBAL_H
#define __SS_GLOBAL_H
/*
 * This variable is set to one when the security server
 * has completed initialization.
 */
extern int ss_initialized;

#ifdef __TDB_CDV__
#include <linux/kernel.h>	/* printk */
#include <linux/slab.h>		/* kmalloc, kfree */
#include <linux/fs.h>		/* read, write, open */
#include <linux/file.h>
#include <linux/string.h>	/* strcpy, strncpy, strcmp */
#include <linux/in.h>		/* IPPROTO_* */
#include <linux/ctype.h>
#include <linux/flask/flask.h>
#include <linux/flask/avc.h>
#include <linux/flask/avc_ss.h>
#include <linux/flask/security.h>
#include <asm/system.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>

#define malloc(size) kmalloc(size, SAFE_ALLOC)
#define free(ptr) kfree(ptr)


typedef struct file FILE;

static __inline FILE *fopen(char *path, char *type)
{
	struct nameidata nd;
	struct file *file;
	int err = 0;

	if (strcmp(type, "r"))
		panic("fopen");

	if (path_init(path, LOOKUP_FOLLOW | LOOKUP_POSITIVE, &nd)) 
		err = path_walk(path, &nd);
	if (err)
		return NULL;

	if (!ss_initialized)
		inode_security_set_sid(nd.dentry->d_inode,SECINITSID_POLICY);

	if (!S_ISREG(nd.dentry->d_inode->i_mode)) 
		goto bad;

	file = dentry_open(nd.dentry, nd.mnt, O_RDONLY);
	if (IS_ERR(file))
		return NULL;
	else 
		return file;

bad:
	path_release(&nd);
	return NULL;
}


static __inline int fclose(FILE * stream)
{
	fput(stream);
	return 0;
}


static __inline ssize_t fread(void *buf, size_t size, size_t nitems, FILE * fp)
{
	mm_segment_t old_fs;
	ssize_t rc;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = (fp)->f_op->read((fp), (buf), (nitems * size), &(fp)->f_pos);
	set_fs(old_fs);
	if (rc > 0)
		return (rc / size);
	return 0;
}

#define printf printk

#define exit(error_code) panic("SS: exiting (%d)",error_code)
#endif /* __TDB_CDV__ */

#endif /* __SS_GLOBAL_H */
