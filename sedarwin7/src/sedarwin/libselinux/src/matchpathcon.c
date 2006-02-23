#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include "policy.h"

/*
 * A file security context specification.
 */
typedef struct spec {
	char *regex_str;	/* regular expession string for diagnostic messages */
	char *type_str;		/* type string for diagnostic messages */
	char *context;		/* context string */
	regex_t regex;		/* compiled regular expression */
	mode_t mode;		/* mode format value */
	int matches;		/* number of matching pathnames */
	int hasMetaChars; 	/* indicates whether the RE has 
				   any meta characters.  
				   0 = no meta chars 
				   1 = has one or more meta chars */
	int stem_id;		/* indicates which of the stem-compression
				 * items it matches */
} spec_t;

typedef struct stem {
	char *buf;
	int len;
} stem_t;

static stem_t *stem_arr = NULL;
static int num_stems = 0;
static int alloc_stems = 0;

static const char * const regex_chars = ".^$?*+|[({";

/* Return the length of the text that can be considered the stem, returns 0
 * if there is no identifiable stem */
static int get_stem_from_spec(const char * const buf)
{
	const char *tmp = strchr(buf + 1, '/');
	const char *ind;

	if(!tmp)
		return 0;

	for(ind = buf; ind < tmp; ind++)
	{
		if(strchr(regex_chars, (int)*ind))
			return 0;
	}
	return tmp - buf;
}

/* return the length of the text that is the stem of a file name */
static int get_stem_from_file_name(const char * const buf)
{
	const char *tmp = strchr(buf + 1, '/');

	if(!tmp)
		return 0;
	return tmp - buf;
}

/* find the stem of a file spec, returns the index into stem_arr for a new
 * or existing stem, (or -1 if there is no possible stem - IE for a file in
 * the root directory or a regex that is too complex for us).  Makes buf
 * point to the text AFTER the stem. */
static int find_stem_from_spec(const char **buf)
{
	int i;
	int stem_len = get_stem_from_spec(*buf);

	if(!stem_len)
		return -1;
	for(i = 0; i < num_stems; i++)
	{
		if(stem_len == stem_arr[i].len && !strncmp(*buf, stem_arr[i].buf, stem_len))
		{
			*buf += stem_len;
			return i;
		}
	}
	if(num_stems == alloc_stems)
	{
		alloc_stems = alloc_stems * 2 + 16;
		stem_arr = realloc(stem_arr, sizeof(stem_t) * alloc_stems);
		if(!stem_arr)
			return -1;
	}
	stem_arr[num_stems].len = stem_len;
	stem_arr[num_stems].buf = malloc(stem_len + 1);
	if(!stem_arr[num_stems].buf)
		return -1;
	memcpy(stem_arr[num_stems].buf, *buf, stem_len);
	stem_arr[num_stems].buf[stem_len] = '\0';
	num_stems++;
	*buf += stem_len;
	return num_stems - 1;
}

/* find the stem of a file name, returns the index into stem_arr (or -1 if
 * there is no match - IE for a file in the root directory or a regex that is
 * too complex for us).  Makes buf point to the text AFTER the stem. */
static int find_stem_from_file(const char **buf)
{
	int i;
	int stem_len = get_stem_from_file_name(*buf);

	if(!stem_len)
		return -1;
	for(i = 0; i < num_stems; i++)
	{
		if(stem_len == stem_arr[i].len && !strncmp(*buf, stem_arr[i].buf, stem_len))
		{
			*buf += stem_len;
			return i;
		}
	}
	return -1;
}

/*
 * The array of specifications, initially in the
 * same order as in the specification file.
 * Sorting occurs based on hasMetaChars
 */
static spec_t *spec_arr;
static int nspec;

/*
 * An association between an inode and a 
 * specification.  
 */
typedef struct file_spec {
	ino_t ino;		/* inode number */
	int specind;		/* index of specification in spec */
	char *file;		/* full pathname for diagnostic messages about conflicts */
	struct file_spec *next;	/* next association in hash bucket chain */
} file_spec_t;

/* Determine if the regular expression specification has any meta characters. */
static void spec_hasMetaChars(struct spec *spec)
{
	char *c;
	int len;
	char *end;

	c = spec->regex_str;
	len = strlen(spec->regex_str);
	end = c + len;

	spec->hasMetaChars = 0; 

	/* Look at each character in the RE specification string for a 
	 * meta character. Return when any meta character reached. */
	while (c != end) {
		switch(*c) {
			case '.':
			case '^':
			case '$':
			case '?':
			case '*':
			case '+':
			case '|':
			case '[':
			case '(':
			case '{':
				spec->hasMetaChars = 1;
				return;
			case '\\':		/* skip the next character */
				c++;
				break;
			default:
				break;

		}
		c++;
	}
	return;
}

static int matchpathcon_init(void)
{
	FILE *fp;
	char line_buf[BUFSIZ + 1], *buf_p;
	char *regex, *type, *context;
	char *anchored_regex;
	int items, len, lineno, pass, regerr, i, j;
	spec_t *spec_copy;

	/* Open the specification file. */
	if ((fp = fopen(selinux_file_context_path(), "r")) == NULL)
		return -1;

	/* 
	 * Perform two passes over the specification file.
	 * The first pass counts the number of specifications and
	 * performs simple validation of the input.  At the end
	 * of the first pass, the spec array is allocated.
	 * The second pass performs detailed validation of the input
	 * and fills in the spec array.
	 */
	for (pass = 0; pass < 2; pass++) {
		lineno = 0;
		nspec = 0;
		while (fgets(line_buf, sizeof line_buf, fp)) {
			lineno++;
			len = strlen(line_buf);
			if (line_buf[len - 1] != '\n') {
				errno = EINVAL;
				return -1;
			}
			line_buf[len - 1] = 0;
			buf_p = line_buf;
			while (isspace(*buf_p))
				buf_p++;
			/* Skip comment lines and empty lines. */
			if (*buf_p == '#' || *buf_p == 0)
				continue;
			items =
			    sscanf(line_buf, "%as %as %as", &regex, &type,
				   &context);
			if (items < 2) {
				errno = EINVAL;
				return -1;
			} else if (items == 2) {
				/* The type field is optional. */
				free(context);
				context = type;
				type = 0;
			}

			if (pass == 1) {
				/* On the second pass, compile and store the specification in spec. */
				const char *reg_buf = regex;
				spec_arr[nspec].stem_id = find_stem_from_spec(&reg_buf);
				spec_arr[nspec].regex_str = regex;

				/* Anchor the regular expression. */
				len = strlen(reg_buf);
				anchored_regex = malloc(len + 3);
				if (!anchored_regex)
					return -1;
				sprintf(anchored_regex, "^%s$", reg_buf);

				/* Compile the regular expression. */
				regerr =
				    regcomp(&spec_arr[nspec].regex,
					    anchored_regex,
					    REG_EXTENDED | REG_NOSUB);
				free(anchored_regex);
				if (regerr < 0) {
					errno = EINVAL;
					return -1;
				}

				/* Convert the type string to a mode format */
				spec_arr[nspec].type_str = type;
				spec_arr[nspec].mode = 0;
				if (!type)
					goto skip_type;
				len = strlen(type);
				if (type[0] != '-' || len != 2) {
					errno = EINVAL;
					return -1;
				}
				switch (type[1]) {
				case 'b':
					spec_arr[nspec].mode = S_IFBLK;
					break;
				case 'c':
					spec_arr[nspec].mode = S_IFCHR;
					break;
				case 'd':
					spec_arr[nspec].mode = S_IFDIR;
					break;
				case 'p':
					spec_arr[nspec].mode = S_IFIFO;
					break;
				case 'l':
					spec_arr[nspec].mode = S_IFLNK;
					break;
				case 's':
					spec_arr[nspec].mode = S_IFSOCK;
					break;
				case '-':
					spec_arr[nspec].mode = S_IFREG;
					break;
				default:
					errno = EINVAL;
					return -1;
				}

			      skip_type:

				spec_arr[nspec].context = context;

				if (strcmp(context, "<<none>>")) {
					if (security_check_context(context) < 0 && errno != ENOENT) {
						errno = EINVAL;
						return -1;
					}
				}

				/* Determine if specification has 
				 * any meta characters in the RE */
				spec_hasMetaChars(&spec_arr[nspec]);
			}

			nspec++;
			if (pass == 0) {
				free(regex);
				if (type)
					free(type);
				free(context);
			}
		}

		if (pass == 0) {
			if (nspec == 0)
				return -1;
			if ((spec_arr = malloc(sizeof(spec_t) * nspec)) ==
			    NULL)
				return -1;
			bzero(spec_arr, sizeof(spec_t) * nspec);
			rewind(fp);
		}
	}
	fclose(fp);

	/* Move exact pathname specifications to the end. */
	spec_copy = malloc(sizeof(spec_t) * nspec);
	if (!spec_copy)
		return -1;
	j = 0;
	for (i = 0; i < nspec; i++) {
		if (spec_arr[i].hasMetaChars)
			memcpy(&spec_copy[j++], &spec_arr[i], sizeof(spec_t));
	}
	for (i = 0; i < nspec; i++) {
		if (!spec_arr[i].hasMetaChars)
			memcpy(&spec_copy[j++], &spec_arr[i], sizeof(spec_t));
	}
	free(spec_arr);
	spec_arr = spec_copy;

	return 0;
}


int matchpathcon(const char *name, 
		 mode_t mode,
		 security_context_t *con)
{
	int i, ret, file_stem;
	const char *buf = name;

	if (!nspec) {
		ret = matchpathcon_init();
		if (ret < 0)
			return ret;
		if (!nspec) {
			errno = ENOENT;
			return -1;
		}
	}

	file_stem = find_stem_from_file(&buf);

	/* 
	 * Check for matching specifications in reverse order, so that
	 * the last matching specification is used.
	 */
	for (i = nspec - 1; i >= 0; i--)
	{
		/* if the spec in question matches no stem or has the same
		 * stem as the file AND if the spec in question has no mode
		 * specified or if the mode matches the file mode then we do
		 * a regex check	*/
		if( (spec_arr[i].stem_id == -1 || spec_arr[i].stem_id == file_stem)
		  && (!mode || !spec_arr[i].mode || ( (mode & S_IFMT) == spec_arr[i].mode ) ) )
		{
			if(spec_arr[i].stem_id == -1)
				ret = regexec(&spec_arr[i].regex, name, 0, NULL, 0);
			else
				ret = regexec(&spec_arr[i].regex, buf, 0, NULL, 0);
			if (ret == 0)
				break;

			if (ret == REG_NOMATCH)
				continue;
			/* else it's an error */
			return -1;
		}
	}

	if (i < 0) {
		/* No matching specification. */
		errno = ENOENT;
		return -1;
	}

	spec_arr[i].matches++;

	*con = strdup(spec_arr[i].context);
	if (!(*con))
		return -1;
	return 0;
}

