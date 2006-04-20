#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <dlfcn.h>

#include "dso.h"
#include "policy.h"
#include "selinux_internal.h"

char *selinux_mnt = NULL;
int context_translations hidden;
void *translation_lib_handle hidden;

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
	/* These make no sense in sebsd */
	//init_selinuxmnt();
	//init_translations();
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{
	//fini_translations();
	//fini_selinuxmnt();
}
