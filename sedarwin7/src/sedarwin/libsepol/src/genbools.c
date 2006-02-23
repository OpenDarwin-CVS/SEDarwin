#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <sepol/policydb.h>
#include <sepol/conditional.h>

#include "private.h"

static char *strtrim(char *dest, char *source, int size) {
	int i=0;
	char *ptr=source;
	i=0;
	while(isspace(*ptr) && i < size) {
		ptr++;
		i++;
	}
	strncpy(dest,ptr,size);
	for(i=strlen(dest)-1; i> 0; i--) {
		if (!isspace(dest[i])) break;
	}
	dest[i+1]='\0';
	return dest;
}

static int load_booleans(struct policydb *policydb, char *path) {
	FILE *boolf;
	char buffer[BUFSIZ];
	char name[BUFSIZ];
	char name1[BUFSIZ];
	int val;
	int errors=0;
	struct cond_bool_datum *datum;

	boolf = fopen(path,"r");
	if (boolf == NULL) 
		return -1;

        while (fgets(buffer, sizeof(buffer), boolf)) {
		char *tok=strtok(buffer,"=");
		if (tok) {
			strncpy(name1,tok, BUFSIZ-1);
			strtrim(name,name1,BUFSIZ-1);
			if ( name[0]=='#' ) continue;
			tok=strtok(NULL,"\0");
			if (tok) {
				while (isspace(*tok)) tok++;
				val = -1;
				if (isdigit(tok[0]))
					val=atoi(tok);
				else if (!strncasecmp(tok, "true", sizeof("true")-1))
					val = 1;
				else if (!strncasecmp(tok, "false", sizeof("false")-1))
					val = 0;
				if (val != 0 && val != 1) {
					fprintf(stderr,"illegal value for boolean %s=%s\n", name, tok);
					errors++;
					continue;
				}

				datum = hashtab_search(policydb->p_bools.table, name);
				if (!datum) {
					fprintf(stderr,"unknown boolean %s\n", name);
					errors++;
					continue;
				}
				datum->state = val;
			}
		}
	}
	fclose(boolf);

	if (errors)
		errno = EINVAL;

	return errors ? -1 : 0;
}

int sepol_genbools(void *data, size_t len, char *booleans)
{
	struct policydb policydb;
	struct policy_file pf;
	int rc;

	pf.type = PF_USE_MEMORY;
	pf.data = data;
	pf.len = len;
	if (policydb_read(&policydb,&pf, 0)) {
		fprintf(stderr, "Can't read binary policy:  %s\n",
			strerror(errno));
		return -1;
	}

	/* Preserve the policy version of the original policy
	   for the new policy. */
	sepol_set_policyvers(policydb.policyvers);

	if (load_booleans(&policydb, booleans) < 0) {
		fprintf(stderr, "Warning!  Error while reading %s:  %s\n",
			booleans, strerror(errno));
	}

	if (evaluate_conds(&policydb) < 0) {
		fprintf(stderr, "Error while re-evaluating conditionals: %s\n",
			strerror(errno));
		return -1;
	}

	pf.data = data;
	pf.len = len;
	rc = policydb_write(&policydb, &pf);
	if (rc) {
		fprintf(stderr, "Can't write binary policy:  %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

int sepol_genbools_array(void *data, size_t len, char **names, int *values, int nel)
{
	struct policydb policydb;
	struct policy_file pf;
	int rc, i, errors = 0;
	struct cond_bool_datum *datum;

	pf.type = PF_USE_MEMORY;
	pf.data = data;
	pf.len = len;
	if (policydb_read(&policydb,&pf, 0)) {
		fprintf(stderr, "Can't read binary policy:  %s\n",
			strerror(errno));
		return -1;
	}

	/* Preserve the policy version of the original policy
	   for the new policy. */
	sepol_set_policyvers(policydb.policyvers);

	for (i = 0; i < nel; i++) {
		datum = hashtab_search(policydb.p_bools.table, names[i]);
		if (!datum) {
			fprintf(stderr,"unknown boolean %s\n", names[i]);
			errors++;
			continue;
		}
		if (values[i] != 0 && values[i] != 1) {
			fprintf(stderr,"illegal value %d for boolean %s\n", values[i], names[i]);
			errors++;
			continue;
		}
		datum->state = values[i];
	}

	if (evaluate_conds(&policydb) < 0) {
		fprintf(stderr, "Error while re-evaluating conditionals: %s\n",
			strerror(errno));
		return -1;
	}

	pf.data = data;
	pf.len = len;
	rc = policydb_write(&policydb, &pf);
	if (rc) {
		fprintf(stderr, "Can't write binary policy:  %s\n",
			strerror(errno));
		return -1;
	}
	if (errors) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}


