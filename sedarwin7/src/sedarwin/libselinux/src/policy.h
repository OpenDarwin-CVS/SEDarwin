#ifndef _POLICY_H_
#define _POLICY_H_

/* Private definitions used internally by libselinux. */

/* xattr name for SELinux attributes. */
#define XATTR_NAME_SELINUX "security.selinux"

/* Initial length guess for getting contexts. */
#define INITCONTEXTLEN 255

/* selinuxfs mount point */
extern char *selinux_mnt;

#define FILECONTEXTS "/etc/security/selinux/file_contexts"

#endif


