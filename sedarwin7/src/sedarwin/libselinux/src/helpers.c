#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <selinux/class_to_string.h>
#include <selinux/common_perm_to_string.h>

typedef unsigned int u32;
typedef unsigned short u16; 
#include <selinux/av_inherit.h>
#include <selinux/av_perm_to_string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define NCLASSES ARRAY_SIZE(class_to_string)
#define NVECTORS ARRAY_SIZE(av_perm_to_string)

security_class_t string_to_security_class(const char *s)
{
	unsigned int val;

	if (isdigit(s[0])) {
		val = atoi(s);
		if (val > 0 && val < NCLASSES)
			return val;
	} else { 
		for (val = 0; val < NCLASSES; val++) {
			if (strcmp(s, class_to_string[val]) == 0)
				return val;
		}
	}
	
	return 0;
}

access_vector_t string_to_av_perm(
	security_class_t tclass,
	const char *s)
{
        char          **common_pts = 0;
        access_vector_t perm, common_base = 0;
        unsigned int       i;
 
 
        for (i = 0; i < ARRAY_SIZE(av_inherit); i++) {
                if (av_inherit[i].tclass == tclass) {
                        common_pts = av_inherit[i].common_pts;
                        common_base = av_inherit[i].common_base;
                        break;
                }
        }

	i = 0;
	perm = 1;
	while (perm < common_base) {
		if (strcmp(s, common_pts[i]) == 0)
			return perm;
		perm <<= 1;
		i++;
	}

	for (i = 0; i < NVECTORS; i++) {
		if ((av_perm_to_string[i].tclass == tclass) &&
		    (strcmp(s, av_perm_to_string[i].name) == 0))
			return av_perm_to_string[i].value;
	}
	
	return 0;
}

void print_access_vector(
        security_class_t tclass,
        access_vector_t av)
{
        char          **common_pts = 0;
        access_vector_t common_base = 0;
        unsigned int             i, i2, perm;
 
 
        if (av == 0) {
                printf(" null");
                return;
        }

        for (i = 0; i < ARRAY_SIZE(av_inherit); i++) {
                if (av_inherit[i].tclass == tclass) {
                        common_pts = av_inherit[i].common_pts;
                        common_base = av_inherit[i].common_base;
                        break;
                }
        }

        printf(" {");
        i = 0;  
        perm = 1;
        while (perm < common_base) {
                if (perm & av)
                        printf(" %s", common_pts[i]);
                i++;
                perm <<= 1;
        }

        while (i < sizeof(access_vector_t) * 8) {
                if (perm & av) {
                        for (i2 = 0; i2 < NVECTORS; i2++) {
                                if ((av_perm_to_string[i2].tclass == tclass) &&
                                    (av_perm_to_string[i2].value == perm))
                                        break;
                        }
                        if (i2 < NVECTORS)
                                printf(" %s", av_perm_to_string[i2].name);
                }
                i++;
                perm <<= 1;
        }
 
        printf(" }");
}
