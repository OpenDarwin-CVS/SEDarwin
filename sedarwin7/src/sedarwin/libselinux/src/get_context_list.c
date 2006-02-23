#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/get_context_list.h>

#define USERPRIORITY 1
#define SYSTEMPRIORITY 2

int get_default_context(const char* user, 
			security_context_t fromcon,
			security_context_t *newcon)
{
    security_context_t *conary;
    int rc;

    rc = get_ordered_context_list(user, fromcon, &conary);
    if (rc <= 0)
	    return -1;

    *newcon = strdup(conary[0]);
    if (!(*newcon))
	    return -1;
    freeconary(conary);
    return 0;
}
    
/* find_line - Seach for an entry in 'infile' that matches the context 'con'
               stripped of the user identity.  If an entry is found, the 
	       remainder of the line is stored in line.  A 0 is returned if 
	       an entry is found, and a 1 is returned otherwise.
*/
static int find_line (FILE *infile, security_context_t con, char *line, 
                      size_t length)
{
    char *current_line;
    char *ptr, *ptr2 = NULL;
    int found = 0;
    char *cc_str = 0;
    size_t cc_len = 0;

    /* Skip the user field. */
    cc_str = index(con, ':');
    if (!cc_str)
	    return -1;
    cc_str++;
    cc_len = strlen(cc_str);
    if (!cc_len)
	    return -1;

    current_line = malloc (length);
    if (!current_line)
	    return (-1);

    while (!feof (infile)) {
	if (!fgets(current_line, length, infile)) {
		free(current_line);
		return -1;
	}
	if (current_line[strlen(current_line) - 1])
		current_line[strlen(current_line) - 1] = 0;
            
	/* Skip leading whitespace before the partial context. */
	ptr = current_line;
        while (*ptr && isspace(*ptr))
		ptr++;

        if (!(*ptr))
		continue;

	/* Find the end of the partial context. */
	ptr2 = ptr;
	while (*ptr2 && !isspace(*ptr2))
		ptr2++;
	if (!(*ptr2))
		continue;

	if (strncmp (cc_str, ptr, cc_len) == 0) {
		found = 1;
		break;
	}
    }

    if (!found) {
	    free(current_line);
	    return -1;
    }

    /* Skip whitespace. */
    while (*ptr2 && isspace(*ptr2))
	    ptr2++;
    if (!(*ptr2)) {
	    free(current_line);
	    return -1;
    }

    /* Copy the remainder of the line. */
    strncpy(line, ptr2, length - 1);
    line[length-1] = 0;
    free (current_line);
    return 0;
}
         

/* list_from_string - given a string, and a user name, pull out the partial
                      security contexts from the string and combine with the 
                      username to make a full security context.  Each security
                      context will be checked, and if valid, stored in 
		      pri_list.  The number of elements stored in pri_list 
		      is returned.
*/
static int list_from_string (char *instr, const char *user, 
                             security_context_t *pri_list, 
                             int pri_length)
{
    char *ptr, *ptr2;
    size_t length;
    security_context_t current_context;
    size_t current_context_len;
    int count = 0;

    ptr = instr;
    while (*ptr && (count < pri_length))
    { 
        /* Skip leading whitespace */
        while (*ptr && isspace(*ptr))
		ptr++;
	if (!(*ptr))
		return count;

        /* Find the end of this partial context. */
        ptr2 = ptr;
        while (*ptr2 && !isspace(*ptr2))
		ptr2++;

	/* Generate a full context with the user identity. */
        length = ptr2  - ptr;
	current_context_len = length + strlen (user) + 2;
	current_context = (security_context_t)malloc(current_context_len);
	if (current_context == NULL)
		return count;

	strcpy (current_context, user);
	strcat (current_context, ":");
	strncat (current_context, ptr, length);
	current_context[current_context_len-1] = '\0';

	/* Check the validity of the context, i.e. user->role,
	   role->domain authorizations. */
	if (!security_check_context(current_context)) {
		pri_list[count] = current_context;
                count++;
	}
	else
		freecon(current_context);
	
	ptr += length;
    }

    return count;
}


/* get_context_list - given starting (from) context and a user name,
                      stores in pri_list a list of contexts based on 
                      configuration information from infile.  The int 
                      pri_length is the maximum number of contexts that will  
                      fit in pri_list.  Returns the number of contexts stored 
                      in pri_list or -1 on error.
*/
static int get_context_list (FILE *infile, security_context_t fromcon, 
                             const char *user, security_context_t *pri_list, 
                             int pri_length)
{
    int ret_val = 0;        /* Used for return values                    */
    char line[255];         /* The line from the configuration file that
                               matches the current sid                   */

    /* Find the line in infile that matches fromcon */
    ret_val = find_line (infile, fromcon, line, sizeof line);
    if (ret_val)
	    return -1;

    /* Get the contexts from this line */
    ret_val = list_from_string (line, user, pri_list, pri_length);
    return ret_val;
}


/* get_config_priority - given a context and a username, get the context priority 
                         list for that user and place it in pri_list.  The  
                         maximum number of elements allowed is pri_length.  
                         If which equals USERPRIORITY, the list will come
                         from the user's .default_contexts file.  If which 
                         equals SYSTEMPRIORITY, the list will come from the
                         system configuration file.  The number of contexts placed
                         in pri_list is returned.
 */
static int get_config_priority (security_context_t fromcon, const char *user, 
                         security_context_t *pri_list, int pri_length, int which,
                         int default_user_flag)
{
    FILE *config_file;    /* The configuration file                    */
    char *fname = 0;      /* The name of the user's configuration file */
    size_t fname_len;     /* The length of fname                       */
    int retval;           /* The return value                          */

    if (which == USERPRIORITY)
    {
	    char *user_contexts_path = selinux_user_contexts_path();
	    fname_len = strlen(user_contexts_path) + strlen(user) + 2;
	    fname = malloc (fname_len);
	    if (!fname) 
		    return -1;
	    retval = snprintf (fname, fname_len, "%s/%s", user_contexts_path, user);
	    if (retval < 0 || (size_t)retval >= fname_len) {
		    free(fname);
		    return -1;
	    }
	    config_file = fopen (fname, "r");
	    free (fname);
    }
    else if (which == SYSTEMPRIORITY)
    {
        config_file = fopen (selinux_default_context_path(), "r");
    }
    else
    {
        /* Bad which value */
        return -1;
    }

    if (!config_file)
    {
        return -1;
    }
    if (default_user_flag)
        retval = get_context_list (config_file, fromcon, 
                                   SELINUX_DEFAULTUSER, pri_list, 
                                   pri_length);
    else
        retval = get_context_list (config_file, fromcon, user, pri_list, 
                                   pri_length);
    fclose (config_file);
    return retval;
}


/* insert - given a list, a position pos, and a context, inserts the context into the 
            list at pos.  Returns 0 on success, -1 on failure.
 */
static inline int insert (security_context_t *ordered_list, int length, int pos, 
			  security_context_t new_item)
{
    int ret_val = -1;

    if ((pos < length) && (pos >= 0))
    {
        ordered_list[pos] = strdup(new_item);
        ret_val = 0;
    }

    return ret_val;
}


/* complete_ordered_list - given an ordered_list of contexts and a position, 
                           insert all the contexts in init_list that are not 
			   yet in ordered_list into ordered_list
 */
static int complete_ordered_list (security_context_t *ordered_list, int *pos, 
                                  security_context_t *init_list, int *bitmap, 
                                  int length)
{
    int i;
    int ret_val = 0;
    int count = *pos;

    if (*pos) {
      /* If there were any reachable contexts in default_contexts, then omit 
	 any reachable contexts that were not found in default_contexts,
	 as these are typically not contexts that we want to be visible to the
	 user anyway. */
      return *pos;
    }

    for (i = 0; i < length; i++)
    {
        if (!bitmap[i])
        {
            ret_val = insert (ordered_list, length, *pos, init_list[i]);
            if (!ret_val)
            {
                /* Mark that we have already used this context */
                bitmap[i] = 1;
                (*pos)++;
                count++;
            }
        }
    }

    return count;
}


/* locate - given a list, and a context, return the position of the context in the list 
 */
static inline int locate (security_context_t *list, int list_len, security_context_t element)
{
    int i;

    for (i = 0; i < list_len; i++)
	    if (!strcmp(list[i],element))
		return i;

    return -1;
}


/* add_priority_list - given an ordered list of contexts ordered_list, a current
                       position pos, the total list of contexts total_list, and a 
                       priority list pri_list add the contexts from pri_list that 
                       are in total_list, but are not yet in ordered list. 
                       Return 0 on success.
 */
static int add_priority_list (security_context_t *ordered_list, 
                              security_context_t *total_list,
                              int *bitmap, int length, security_context_t *pri_list,
                              int pri_length, int *pos)
{
    int i;
    int location;
    int ret_val = 0;

    for (i = 0; i < pri_length; i++)
    {
        location = locate (total_list, length, pri_list[i]);
        if ((location >= 0) && (location < length) && (!bitmap[location]))
        {
            ret_val = insert (ordered_list, length, *pos, pri_list[i]);
            if (ret_val)
                return ret_val;

            /* Mark that we have already used this context. */
            bitmap[location] = 1;
            (*pos)++;
        }
    }
    return ret_val;
}

int get_failsafe_context(const char* user, 
			 security_context_t *newcon)
{
	FILE *fp;
	char buf[255], *ptr;
	size_t plen, nlen;
	int rc;

	fp = fopen(selinux_failsafe_context_path(), "r");
	if (!fp)
		return -1;

	ptr = fgets(buf, sizeof buf, fp);
	fclose(fp);

	if (!ptr)
		return -1;
	plen = strlen(ptr);
	if (buf[plen-1] == '\n') 
		buf[plen-1] = 0;

 retry:
	nlen = strlen(user)+1+plen+1;
	*newcon = malloc(nlen);
	rc = snprintf(*newcon, nlen, "%s:%s", user, ptr);
	if (rc < 0 || (size_t) rc >= nlen) {
		free(*newcon);
		*newcon = 0;
		return -1;
	}

	/* If possible, check the context to catch
	   errors early rather than waiting until the
	   caller tries to use setexeccon on the context.
	   But this may not always be possible, e.g. if
	   selinuxfs isn't mounted. */
	if (security_check_context(*newcon) && errno != ENOENT) {
		free(*newcon);
		*newcon = 0;
		if (strcmp(user, SELINUX_DEFAULTUSER)) {
			user = SELINUX_DEFAULTUSER;
			goto retry;
		}
		return -1;
	}

	return 0;
}

int get_ordered_context_list (const char *user, 
			      security_context_t fromcon, 
			      security_context_t **list)
{
    security_context_t *init_list=0, *ordered_list;
    char **ptr;
    int rc;
    int *bitmap = 0;            /* An array matching the initial sid list.
                                   Each int corresponds to a sid in the 
                                   initial sid list.  The int will be 1 if 
                                   the corresponding sid has already been 
                                   placed into the ordered list, 0 otherwise */
    int i;                      /* An index into an array                    */
    security_context_t *pri_list;    /* The priority sid list obtained from a 
                                   config file                               */
    int init_len;
    int pri_length;             /* The maximum length of the priority list   */
    int config_length;          /* The actual length of the priority list    */
    int pos = 0;                /* The current position in the ordered list  */
    int default_user_flag = 0;  /* True if the default user is being used    */
    int freefrom = 0;

    if (!fromcon) {
	    /* Get the current context and use it for the starting context */
	    rc = getcon(&fromcon);
	    if (rc < 0)
		    return rc;
	    freefrom = 1;
    }

    rc = security_compute_user(fromcon, user, &init_list);
    if (rc < 0) {
	    /* Retry with the default SELinux user identity. */
	    rc = security_compute_user(fromcon, 
				       SELINUX_DEFAULTUSER, &init_list);
	    if (rc < 0)
		    goto failsafe;
            default_user_flag = 1;
    }
    init_len = 0;
    for (ptr = init_list; *ptr; ptr++) 
	    init_len++;

    if (!init_len)
	    goto failsafe;

    ordered_list = malloc((init_len+1)*sizeof(security_context_t));
    if (!ordered_list) {
	    rc = -1;
	    goto out2;
    }
    for (i = 0; i <= init_len; i++)
	    ordered_list[i] = 0;

    /* Initialize priority list */
    pri_length = 25;
    pri_list = malloc ((pri_length+1) *sizeof(security_context_t));
    if (!pri_list) {
	    rc = -1;
	    goto out3;
    }
    for (i = 0; i <= pri_length; i++)
	    pri_list[i] = 0;
 
    /* Initialize bitmap */
    bitmap = (int *)malloc (init_len*sizeof(int));
    if (!bitmap) {
	    rc = -1;
	    goto out4;
    }
    for (i = 0; i < init_len; i++)
        bitmap[i] = 0;

    /* get the user's default context list; the contexts from here should go
       first in the ordered list */
    config_length = get_config_priority (fromcon, user, pri_list,
                                         pri_length, USERPRIORITY,
                                         default_user_flag);
    add_priority_list (ordered_list, init_list, bitmap, init_len, pri_list,
                       config_length, &pos);

    /* get the contexts from the system config file and add to ordered_list */
    config_length = get_config_priority (fromcon, user, pri_list,
                                         pri_length, SYSTEMPRIORITY,
                                         default_user_flag);
    add_priority_list (ordered_list, init_list, bitmap, init_len, pri_list,
                       config_length, &pos);

    /* finish up the list with the rest of the reachable contexts */
    rc = complete_ordered_list (ordered_list, &pos, init_list, bitmap, 
				init_len);

    free (bitmap);

out4:
    freeconary(pri_list);

out3:
    if (rc < 0)
	    freeconary(ordered_list);
    else 
	    *list = ordered_list;

out2:
    if (init_list)
	    freeconary(init_list);

    if (freefrom)
	    freecon(fromcon);

    return rc;

failsafe:
    ordered_list = malloc(2*sizeof(security_context_t));
    if (!ordered_list) {
	    rc = -1;
	    goto out2;
    }
    ordered_list[0] = ordered_list[1] = 0;
    rc = get_failsafe_context(user, &ordered_list[0]);
    if (rc == 0)
	    rc = 1;
    goto out3;
}
