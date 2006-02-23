#include <selinux/context.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define COMP_USER  0
#define COMP_ROLE  1
#define COMP_TYPE  2
#define COMP_RANGE 3

typedef struct {
        char *current_str; /* This is made up-to-date only when needed */
        char *(component[4]); 
} context_private_t;

/*
 * Allocate a new context, initialized from str.  There must be 3 or
 * 4 colon-separated components and no whitespace.
 */
context_t
context_new(const char *str)
{
        int i,count;
        context_private_t *n = (context_private_t*) malloc(sizeof(context_private_t));
        context_t result = (context_t) malloc(sizeof(context_s_t));
        const char *p,*tok;
        
        if ( n == 0 || result == 0 ) { goto err; }
        n->current_str = n->component[0] = n->component[1] = n->component[2] =
                n->component[3] = 0;
        result->ptr = n;
        for ( i = count = 0, p = str; *p; p++ ) {
                switch ( *p ) { 
                case ':': count++; break;
                case '\n': case '\t': case '\r': case ' ': goto err; /* sanity check */
                }
        }
	/*
	 * Could be anywhere from 2 - 5
	 * e.g user:role:type to user:role:type:sens1:cata-sens2:catb
	 */
        if ( count < 2 || count > 5 ) { /* might not have a range */
                goto err;
        }

        n->component[3] = 0;
        for ( i = 0, tok = str; *tok; i++ ) {
		if (i<3)
                	for ( p = tok; *p && *p != ':'; p++ ) { /* empty */ }
		else
		{
			/* MLS range is one component */
                	for ( p = tok; *p; p++ ) { /* empty */ }
		}
                n->component[i] = (char*) malloc(p-tok+1);
		if (n->component[i] == 0)
		  goto err;
                strncpy(n->component[i],tok,p-tok);
                n->component[i][p-tok] = '\0';
                tok = *p ? p+1 : p;
        }
        return result;
 err:
        context_free(result);
        return 0;
}

static void 
conditional_free(char** v)
{
        if ( *v ) { 
                free(*v); 
        }
        *v = 0;
}

/*
 * free all storage used by a context.  Safe to call with
 * null pointer. 
 */
void 
context_free(context_t context)
{
        context_private_t *n;
        int i;
        if ( context ) {
                n = context->ptr;
                if ( n ) {
                        conditional_free(&n->current_str);
                        for ( i = 0; i < 4; i++ ) {
                                conditional_free(&n->component[i]);
                        }
                        free(n);
                }
                free(context);
        }
}

/*
 * Return a pointer to the string value of the context.
 */

char *
context_str(context_t context)
{
        context_private_t *n = context->ptr;
        int i;
        size_t total = 0;
        conditional_free(&n->current_str);
        for ( i = 0; i < 4; i++ ) {
                if ( n->component[i] ) {
                        total += strlen(n->component[i])+1;
                }
        }
        n->current_str = malloc(total);
        if ( n->current_str != 0 ) {
                strcpy(n->current_str,n->component[0]);
                strcat(n->current_str,":");
                strcat(n->current_str,n->component[1]);
                strcat(n->current_str,":");
                strcat(n->current_str,n->component[2]);
                if ( n->component[3] ) {
                        strcat(n->current_str,":");
                        strcat(n->current_str,n->component[3]);
                }
        }
        return n->current_str;
}

/* Returns nonzero iff failed */

static int set_comp(context_private_t* n,int index, const char *str)
{
        char *t = (char*) malloc(strlen(str)+1);
        const char *p;
        if ( !t ) { return 1; }
        for ( p = str; *p; p++ ) {
                if ( *p == '\t' || *p == ' ' || *p == '\n' || *p == '\r' ||
                     *p == ':' ) {
                        free(t);
                        return 1;
                }
        }
        conditional_free(&n->component[index]);
        n->component[index] = t;
        strcpy(t,str);
        return 0;
}

#define def_get(name,tag) \
const char * context_ ## name ## _get(context_t context) \
{ \
        context_private_t *n = context->ptr; \
        return n->component[tag]; \
}

def_get(type,COMP_TYPE)
def_get(user,COMP_USER)
def_get(range,COMP_RANGE)
def_get(role,COMP_ROLE)

#define def_set(name,tag) \
int context_ ## name ## _set(context_t context, const char* str) \
{ \
        return set_comp(context->ptr,tag,str);\
}

def_set(type,COMP_TYPE)
def_set(role,COMP_ROLE)
def_set(user,COMP_USER)

int context_range_set(context_t context,const char* str)
{
        context_private_t *n = context->ptr;
        if ( ! n->component[COMP_RANGE] ) {
                return 0;
        } else {
                return set_comp(n,COMP_RANGE,str);
        }
}

#ifdef L1TEST

#include "testutils.c"

main()
{
        context_t c1,c2;
        c1 = context_new("user:role:type:levellow-levelhigh");
        c2 = context_new("user2:role2:type2");

        /* see if strings come back unchanged */

        if ( strcmp(context_str(c1),"user:role:type:levellow-levelhigh") ) {
                test_fail("context_str c1");
        }
        if ( strcmp(context_str(c2),"user2:role2:type2") ) {
                test_fail("context_str c2");
        }

        /* get components */

        if ( strcmp(context_role_get(c1),"role") ) {
                test_fail("context_role_get(c1)");
        }
        if ( strcmp(context_user_get(c1),"user") ) {
                test_fail("context_user_get(c1)");
        }
        if ( strcmp(context_type_get(c1),"type") ) {
                test_fail("context_type_get(c1)");
        }
        if ( strcmp(context_range_get(c1),"levellow-levelhigh" ) ) {
                test_fail("context_range_get(c1)");
        }
        if ( strcmp(context_role_get(c2),"role2") ) {
                test_fail("context_role_get(c2)");
        }
        if ( strcmp(context_user_get(c2),"user2") ) {
                test_fail("context_user_get(c2)");
        }
        if ( strcmp(context_type_get(c2),"type2") ) {
                test_fail("context_type_get(c2)");
        }
        if ( context_range_get(c2) != 0 ) {
                test_fail("context_range_get(c2)");
        }

        /* Set components */

        if ( context_type_set(c1,"newtype1") ||
             strcmp(context_type_get(c1),"newtype1") ) {
                test_fail("context_type_set(c1)");
        }
        if ( context_range_set(c1,"newrange1") ||
             strcmp(context_range_get(c1),"newrange1") ) {
                test_fail("context_range_set(c1)");
        }
        if ( context_role_set(c1,"newrole1") ||
             strcmp(context_role_get(c1),"newrole1") ) {
                test_fail("context_role_set(c1)");
        }
        if ( context_user_set(c1,"newuser1") ||
             strcmp(context_user_get(c1),"newuser1") ) {
                test_fail("context_user_set(c1)");
        }

        /* check trying to set a component with whitespace */

        if ( !context_type_set(c1,"new type 1") ) {
                test_fail("context_type_set with whitespace");
        }

        /* check trying to set with a colon */

        if ( !context_range_set(c1,"newrange:1") ) {
                test_fail("context_type_set with colon");
        }

        /* check new value */

        if ( strcmp(context_str(c1),"newuser1:newrole1:newtype1:newrange1") ) {
                test_fail("second context_str(c1)");
        }

        test_print_report();
}
#endif
