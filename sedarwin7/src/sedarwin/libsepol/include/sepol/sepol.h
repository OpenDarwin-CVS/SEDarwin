#ifndef _SEPOL_H_
#define _SEPOL_H_

#include <sys/types.h>

/* Given an existing binary policy (starting at 'data', with length 'len')
   and a boolean configuration file named by 'boolpath', rewrite the binary
   policy for the boolean settings in the boolean configuration file.
   The binary policy is rewritten in place in memory.
   Returns 0 upon success, or -1 otherwise. */
extern int sepol_genbools(void *data, size_t len, char *boolpath);

/* Given an existing binary policy (starting at 'data', with length 'len')
   and boolean settings specified by the parallel arrays ('names', 'values')
   with 'nel' elements, rewrite the binary policy for the boolean settings.  
   The binary policy is rewritten in place in memory.
   Returns 0 upon success or -1 otherwise. */
extern int sepol_genbools_array(void *data, size_t len, char **names, int *values, int nel);


#endif
