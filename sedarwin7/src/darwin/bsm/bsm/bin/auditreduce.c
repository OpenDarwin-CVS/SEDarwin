
/* 
 * Tool used to merge and select audit records from audit trail files 
 */   

/*
 * auditreaduce [options] [audit-trail-file...]
 */   

/*
 * XXX Currently we do not support merging of records from multiple
 * XXX audit trail files
 * XXX We assume that records are sorted chronologically - both wrt to 
 * XXX the records present within the file and between the files themselves
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#include <libbsm.h>
#include "auditreduce.h"


extern char *optarg;
extern int optind, optopt, opterr,optreset;

au_mask_t maskp; /* Used while selecting based on class */
time_t p_atime;/* select records created after this time */
time_t p_btime;/* select records created before this time */
u_int16_t p_evtype; /* The event that we are searching for */
int p_auid; /* audit id */ 
int p_euid; /* effective user id */
int p_egid; /* effective group id */ 
int p_rgid; /* real group id */ 
int p_ruid; /* real user id */ 
int p_subid; /* subject id */

/* Following are the objects (-o option) that we can select upon */
char *p_fileobj = NULL;
char *p_msgqobj = NULL;
char *p_pidobj = NULL;
char *p_semobj = NULL;
char *p_shmobj = NULL;
char *p_sockobj = NULL; 


u_int32_t opttochk = 0;


static void usage(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	fprintf(stderr, "Usage: auditreduce [options] audit-trail-file [....] \n");
	fprintf(stderr, "\tOptions are : \n");
	fprintf(stderr, "\t-A : all records\n");
	fprintf(stderr, "\t-a YYYYMMDD[HH[[MM[SS]]] : after date\n");
	fprintf(stderr, "\t-b YYYYMMDD[HH[[MM[SS]]] : before date\n");
	fprintf(stderr, "\t-c <flags> : matching class\n");
	fprintf(stderr, "\t-d YYYYMMDD : on date\n");
	fprintf(stderr, "\t-e <uid|name>  : effective user\n");
	fprintf(stderr, "\t-f <gid|group> : effective group\n");
	fprintf(stderr, "\t-g <gid|group> : real group\n");
	fprintf(stderr, "\t-j <pid> : subject id \n");
	fprintf(stderr, "\t-m <evno|evname> : matching event\n");
	fprintf(stderr, "\t-o objecttype=objectvalue\n");
	fprintf(stderr, "\t\t file=<pathname>\n");
	fprintf(stderr, "\t\t msgqid=<ID>\n");
	fprintf(stderr, "\t\t pid=<ID>\n");
	fprintf(stderr, "\t\t semid=<ID>\n");
	fprintf(stderr, "\t\t shmid=<ID>\n");
	fprintf(stderr, "\t-r <uid|name> : real user\n");
	fprintf(stderr, "\t-u <uid|name> : audit user\n");
	exit(1);
}

/*
 * Check if the given auid matches the selection criteria
 */
static int select_auid(int au)
{
	/* check if we want to select on auid */
	if(ISOPTSET(opttochk, OPT_u)) {
		if(au != p_auid) {
			return 0;
		}
	}
	return 1;
}

/*
 * Check if the given euid matches the selection criteria
 */
static int select_euid(int euser)
{
	/* check if we want to select on euid */
	if(ISOPTSET(opttochk, OPT_e)) {
		if(euser != p_euid) {
			return 0;
		}
	}
	return 1;
}

/*
 * Check if the given egid matches the selection criteria
 */
static int select_egid(int egrp)
{
	/* check if we want to select on egid */
	if(ISOPTSET(opttochk, OPT_f)) {
		if(egrp != p_egid) {
			return 0;
		}
	}
	return 1;
}

/*
 * Check if the given rgid matches the selection criteria
 */
static int select_rgid(int grp)
{
	/* check if we want to select on rgid */
	if(ISOPTSET(opttochk, OPT_g)) {
		if(grp != p_rgid) {
			return 0;
		}
	}
	return 1;
}

/*
 * Check if the given ruid matches the selection criteria
 */
static int select_ruid(int user)
{
	/* check if we want to select on rgid */
	if(ISOPTSET(opttochk, OPT_r)) {
		if(user != p_ruid) {
			return 0;
		}
	}
	return 1;
}

/*
 * Check if the given subject id (pid) matches the selection criteria
 */
static int select_subid(int subid)
{
	/* check if we want to select on subject uid */
	if(ISOPTSET(opttochk, OPT_j)) {
		if(subid != p_subid) {
			return 0;
		}
	}
	return 1;
}


/*
 * Check if object's pid maches the given pid
 */ 
static int select_pidobj(u_int32_t pid) 
{
	if(ISOPTSET(opttochk, OPT_op)) {
		if(pid != strtol(p_pidobj, (char **)NULL, 10)) {
			return 0;
		}
	} 
	return 1;
}

/*
 * Check if the given ipc object with the given type matches the
 * selection criteria
 */
static int select_ipcobj(u_char type, u_int32_t id, u_int32_t *optchkd)
{
	if(type == AT_IPC_MSG) {
		SETOPT((*optchkd), OPT_om);
		if(ISOPTSET(opttochk, OPT_om)) {
			if(id != strtol(p_msgqobj, (char **)NULL, 10)) {
				return 0;
			}
		}
		return 1;
	}
	else if(type == AT_IPC_SEM) {
		SETOPT((*optchkd), OPT_ose);
		if(ISOPTSET(opttochk, OPT_ose)) {
			if(id != strtol(p_semobj, (char **)NULL, 10)) {
				return 0;
			}
		}
		return 1;
	}
	else if (type == AT_IPC_SHM) {
		SETOPT((*optchkd), OPT_osh);
		if(ISOPTSET(opttochk, OPT_osh)) {
			if(id != strtol(p_shmobj, (char **)NULL, 10)) {
				return 0;
			}
		}
		return 1;
	}

	/*  unknown type -- filter if *any* ipc filtering is required */
	if(ISOPTSET(opttochk, OPT_om)
			|| ISOPTSET(opttochk, OPT_ose)
			|| ISOPTSET(opttochk, OPT_osh)) {
		return 0;
	}

	return 1;	
}


/*
 * Check if the file name matches selection criteria
 */
static int select_filepath(char *path, u_int32_t *optchkd)
{
	char *loc;

	SETOPT((*optchkd), OPT_of);
	if(ISOPTSET(opttochk, OPT_of)) {
		if(p_fileobj[0] == '~') {
			/* object should not be in path */
			loc = strstr(path, p_fileobj + 1);
			if((loc != NULL) && (loc == path)) {
				return 0;
			}
		}
		else {
			/* object should be in path */
			loc = strstr(path, p_fileobj);
			if((loc == NULL) || (loc != path)) {
				return 0;
			}
		}
	}
	return 1;
}



/*
 * Returns 1 if the following pass the selection rules: 
 *
 * before-time, 
 * after time, 
 * date, 
 * class, 
 * event 
 */
static int select_hdr32(tokenstr_t tok, u_int32_t *optchkd)
{
	SETOPT((*optchkd), (OPT_A | OPT_a | OPT_b | OPT_c | OPT_m));

	/* The A option overrides a,b and d */
	if(!ISOPTSET(opttochk, OPT_A)) {
		if(ISOPTSET(opttochk, OPT_a)) {
			if (difftime((time_t)tok.tt.hdr32.s, p_atime) < 0) {
				/* record was created before p_atime */
				return 0;
			}
		}

		if(ISOPTSET(opttochk, OPT_b)) {
			if (difftime(p_btime, (time_t)tok.tt.hdr32.s) < 0) {
				/* record was created after p_btime */
				return 0;
			}
		}
	}

	if(ISOPTSET(opttochk, OPT_c)) {

		/* check if the classes represented by the event matches given class */
		if(au_preselect(tok.tt.hdr32.e_type, &maskp, 
					AU_PRS_BOTH, AU_PRS_USECACHE) != 1) {
			return 0;
		}
	}  

	/* check if event matches */
	if(ISOPTSET(opttochk, OPT_m)) {
		if(tok.tt.hdr32.e_type != p_evtype) {
			return 0;
		}
	}
		
	return 1;
}

/*
 * Return 1 if checks for the the following succeed
 * auid, 
 * euid, 
 * egid, 
 * rgid, 
 * ruid, 
 * process id
 */
static int select_proc32(tokenstr_t tok, u_int32_t *optchkd)
{
	SETOPT((*optchkd), (OPT_u | OPT_e | OPT_f | OPT_g | OPT_r | OPT_op));

	if( !select_auid(tok.tt.proc32.auid)) {
		return 0;
	}
	if( !select_euid(tok.tt.proc32.euid)) {
		return 0;
	}
	if( !select_egid(tok.tt.proc32.egid)) {
		return 0;
	}
	if( !select_rgid(tok.tt.proc32.rgid)) {
		return 0;
	}
	if( !select_ruid(tok.tt.proc32.ruid)) {
		return 0;
	}

	if( !select_pidobj(tok.tt.proc32.pid)) {
		return 0;
	}

	return 1;
}

/*
 * Return 1 if checks for the the following succeed
 * auid, 
 * euid, 
 * egid, 
 * rgid, 
 * ruid, 
 * subject id
 */
static int select_subj32(tokenstr_t tok, u_int32_t *optchkd)
{
	SETOPT((*optchkd), (OPT_u | OPT_e | OPT_f | OPT_g | OPT_r | OPT_j));

	if( !select_auid(tok.tt.subj32.auid)) {
		return 0;
	}
	if( !select_euid(tok.tt.subj32.euid)) {
		return 0;
	}
	if( !select_egid(tok.tt.subj32.egid)) {
		return 0;
	}
	if( !select_rgid(tok.tt.subj32.rgid)) {
		return 0;
	}
	if( !select_ruid(tok.tt.subj32.ruid)) {
		return 0;
	}
	if( !select_subid(tok.tt.subj32.pid)) {
		return 0;
	}
	return 1;
}

/*
 * Read each record from the audit trail. 
 * Check if it is selected after passing through each of the options 
 */
static int select_records(FILE *fp)
{
	u_char *buf;
	tokenstr_t tok;
	int reclen;
   	int bytesread;
	int selected;
	u_int32_t optchkd;

	int err = 0;

	while((reclen = au_read_rec(fp, &buf)) != -1) {

		optchkd = 0;
		bytesread = 0;
		selected = 1;

		while ((selected == 1) && (bytesread < reclen)) {

			if(-1 == au_fetch_tok(&tok, buf + bytesread, reclen - bytesread)) {
				/* is this an incomplete record ? */
				err = 1;
				break;
			}

			/* For each token type we have have different selection criteria */
			switch(tok.id) {
				case AU_HEADER_32_TOKEN :
						selected = select_hdr32(tok, &optchkd);
						break;

				case AU_PROCESS_32_TOKEN :
						selected = select_proc32(tok, &optchkd);
						break;

				case AU_SUBJECT_32_TOKEN :
						selected = select_subj32(tok, &optchkd);
						break;

				case AU_IPC_TOKEN :
						selected = select_ipcobj(tok.tt.ipc.type, tok.tt.ipc.id, &optchkd); 
						break;

				case AU_FILE_TOKEN :
						selected = select_filepath(tok.tt.file.name, &optchkd);
						break;

				case AU_PATH_TOKEN :
						selected = select_filepath(tok.tt.path.path, &optchkd);
						break;	

				/* 
				 * The following tokens dont have any relevant attributes 
				 * that we can select upon
				 */
				case AU_TRAILER_TOKEN :
				case AU_ARG32_TOKEN :
				case AU_ATTR32_TOKEN :
				case AU_EXIT_TOKEN :
				case AU_NEWGROUPS_TOKEN :
				case AU_IN_ADDR_TOKEN :
				case AU_IP_TOKEN :
				case AU_IPCPERM_TOKEN :
				case AU_IPORT_TOKEN :
				case AU_OPAQUE_TOKEN :
				case AU_RETURN_32_TOKEN :
				case AU_SEQ_TOKEN :
				case AU_TEXT_TOKEN :
				case AU_ARB_TOKEN :
				case AU_SOCK_TOKEN :
				default:
						break;
			}

			bytesread += tok.len;
		}

		if((selected == 1) && (!err)) {

			/* check if all the options were matched */
			if(!(opttochk & ~optchkd)) {
				/* XXX write this record to the output file */

				/* default to stdout */
				fwrite(buf, 1, reclen, stdout);
			}
		}

		free(buf);
	}

	return 0;
}


/* 
 * The -o option has the form object_type=object_value
 * Identify the object components
 */
void parse_object_type(char *name, char *val)
{
	if(val == NULL)
		return;

	if(!strcmp(name, FILEOBJ)) {
		p_fileobj = val;
		SETOPT(opttochk, OPT_of);
	}
	else if( !strcmp(name, MSGQIDOBJ)) {
		p_msgqobj = val;
		SETOPT(opttochk, OPT_om);
	}
	else if( !strcmp(name, PIDOBJ)) {
		p_pidobj = val;
		SETOPT(opttochk, OPT_op);
	}
	else if( !strcmp(name, SEMIDOBJ)) {
		p_semobj = val;
		SETOPT(opttochk, OPT_ose);
	}
	else if( !strcmp(name, SHMIDOBJ)) {
		p_shmobj = val;
		SETOPT(opttochk, OPT_osh);
	}
	else if( !strcmp(name, SOCKOBJ)) {
		p_sockobj = val;
		SETOPT(opttochk, OPT_oso);
	}
	else {
		usage("unknown value for -o");
	}
}


int main(int argc, char **argv)
{
	char ch;
	int i;
	FILE  *fp;
	char *objval;
	struct tm tm;
	au_event_t *n;
	struct passwd *pw;
	struct group *grp;

	char *converr = NULL;
	char timestr[100];

	while((ch = getopt(argc, argv, "Aa:b:c:d:e:f:g:j:m:o:r:u:")) != -1) {

		switch(ch) {

			case 'A':	SETOPT(opttochk, OPT_A);
					break;


			case 'a':	if(ISOPTSET(opttochk, OPT_a)) {
						usage("d is exclusive with a and b");
					}
					SETOPT(opttochk, OPT_a);
					strptime(optarg, "%Y%m%d%H%M%S", &tm);
					strftime(timestr, 99, "%Y%m%d%H%M%S", &tm);
					//fprintf(stderr, "Time converted = %s\n", timestr);
					p_atime = mktime(&tm);
					break; 	

			case 'b':	if(ISOPTSET(opttochk, OPT_b)) {
						usage("d is exclusive with a and b");
					}
					SETOPT(opttochk, OPT_b);
					strptime(optarg, "%Y%m%d%H%M%S", &tm); 
					strftime(timestr, 99, "%Y%m%d%H%M%S", &tm);
					//fprintf(stderr, "Time converted = %s\n", timestr);
					p_btime = mktime(&tm);
					break; 	

			case 'c':	if(0 != getauditflagsbin(optarg, &maskp)) {
						/* Incorrect class */
						usage("Incorrect class");
					}
					SETOPT(opttochk, OPT_c);
					break;

			case 'd':	if(ISOPTSET(opttochk, OPT_b) || ISOPTSET(opttochk, OPT_a)) {
						usage("d is exclusive with a and b");
					}
					SETOPT(opttochk, OPT_d);
					strptime(optarg, "%Y%m%d", &tm);
					strftime(timestr, 99, "%Y%m%d", &tm);
					//fprintf(stderr, "Time converted = %s\n", timestr);
					p_atime = mktime(&tm);

					tm.tm_hour = 23; tm.tm_min = 59; tm.tm_sec = 59;
					strftime(timestr, 99, "%Y%m%d", &tm);
					//fprintf(stderr, "Time converted = %s\n", timestr);
					p_btime = mktime(&tm);
					break;

			case 'e':	p_euid = strtol(optarg, &converr, 10);
					if(*converr != '\0') {
						/* Try the actual name */
						if((pw = getpwnam(optarg)) == NULL) {
							break;
						}
						p_euid = pw->pw_uid;
					}
					SETOPT(opttochk, OPT_e);
					break;

			case 'f':	p_egid = strtol(optarg, &converr, 10);
					if(*converr != '\0') {
						/* try actual group name */
						if((grp = getgrnam(optarg)) == NULL) {
							break;
						}
						p_egid = grp->gr_gid;
					}
					SETOPT(opttochk, OPT_f);
					break;

			case 'g':	p_rgid = strtol(optarg, &converr, 10);
					if(*converr != '\0') {
						/* try actual group name */
						if((grp = getgrnam(optarg)) == NULL) {
							break;
						}
						p_rgid = grp->gr_gid;
					}
					SETOPT(opttochk, OPT_g);
					break;

			case 'j':	p_subid = strtol(optarg, (char **)NULL, 10);
					SETOPT(opttochk, OPT_j);
					break;

			case 'm': 	p_evtype = strtol(optarg, (char **)NULL, 10);
					if(p_evtype == 0) {
						/* Could be the string representation */
						n = getauevnonam(optarg);
						if(n == NULL) {
							usage("Incorrect event name");
						}
						p_evtype = *n;
						free(n);
					}
					SETOPT(opttochk, OPT_m);
					break;

			case 'o':	objval = strchr(optarg, '=');
					if(objval != NULL) {
					 	*objval = '\0';
						objval += 1;			
						parse_object_type(optarg, objval);
					}
					break;

			case 'r':	p_ruid = strtol(optarg, &converr, 10);
					if(*converr != '\0') {
						if((pw = getpwnam(optarg)) == NULL) {
							break;
						}
						p_ruid = pw->pw_uid;
					}
					SETOPT(opttochk, OPT_r);
					break;

			case 'u':	p_auid = strtol(optarg, &converr, 10);
					if(*converr != '\0') {
						if((pw = getpwnam(optarg)) == NULL) {
							break;
						}
						p_auid = pw->pw_uid;
					}
					SETOPT(opttochk, OPT_u);
					break;

			case '?':
			default :
					usage("Unknown option");
		}
	}

	/* For each of the files passed as arguments dump the contents */
	if(optind == argc) {
		// XXX should look in the default directory for audit trail files
		return -1;
	}

	// XXX we should actually be merging records here
	for (i = optind; i < argc; i++) {
		fp = fopen(argv[i], "r");
		if((fp == NULL) || (-1 == select_records(fp))) {
			perror(argv[i]);
		}
		if(fp != NULL)
			fclose(fp);	
	}

	return 1;
}
