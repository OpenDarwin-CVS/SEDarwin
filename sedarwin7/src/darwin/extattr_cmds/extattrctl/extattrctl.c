/*-
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: $
 */
/*
 * Developed by the TrustedBSD Project.
 * Support for file system extended attribute.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/extattr.h>
#include <sys/param.h>
#include <sys/mount.h>

#include <hfs/hfs_extattr.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int initattr(int argc, char *argv[]);
int showattr(int argc, char *argv[]);
long num_inodes_by_path(char *path);
void usage(void);

void
usage()
{

	fprintf(stderr,
	    "usage:\n"
#if 0
	    "  extattrctl start path\n"
	    "  extattrctl stop path\n"
	    "  extattrctl initattr [-f] [-p path] [-i initial_value ] attrsize attrfile\n"
	    "  extattrctl showattr attrfile\n"
	    "  extattrctl enable path attrnamespace attrname attrfile\n"
	    "  extattrctl disable path attrnamespace attrname\n");
#else
	    "  extattrctl initattr [-f] [-p path] [-i initial_value ] attrsize attrfile\n"
	    "  extattrctl showattr attrfile\n");
#endif
	exit(-1);
}

long
num_inodes_by_path(char *path)
{
	struct statfs	buf;
	int	error;

	error = statfs(path, &buf);
	if (error) {
		perror("statfs");
		return (-1);
	}

	return (buf.f_files);
}

int
verify_paths(const char *fs_path, const char *attr_path)
{
	int error;
	struct statfs fs1, fs2;
	
	error = statfs(fs_path, &fs1);
	if (error) {
		perror("statfs");
		return (-1);
	}
	error = statfs(attr_path, &fs2);
	if (error) {
		perror("statfs");
		return (-1);
	}
	
	if (memcmp(&fs1.f_fsid, &fs2.f_fsid, sizeof(fsid_t)) != 0) {
		printf("Warning, attribute backing file is not located on \n"
		    "the same file system as the preallocation path.\n"
		    "Continuing...\n");
	}
	return (0);
}


int
initattr(int argc, char *argv[])
{
	struct hfs_extattr_fileheader	uef;
	char	*fs_path = NULL;
	char	*zero_buf = NULL;
	char	*initial_value = NULL;
	long	loop, num_inodes;
	int	ch, i, error, chunksize, overwrite = 0, flags;
	struct	hfs_extattr_header header;
	int	headersize;

	optind = 0;
	while ((ch = getopt(argc, argv, "fi:p:")) != -1)
		switch (ch) {
		case 'f':
			overwrite = 1;
			break;
		case 'p':
			if ((fs_path = strdup(optarg)) == NULL) {
				perror("strdup");
				return(-1);
			}
			break;
		case 'i':
			if ((initial_value = strdup(optarg)) == NULL) {
				perror("strdup");
				return(-1);
			}
			break;
		case '?':
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	if ((initial_value != NULL) && (fs_path == NULL)) {
		fprintf(stderr,"Error, initial value specified, but -p "
		    "was not specified\n");
		usage();
	}

	if (overwrite)
		flags = O_CREAT | O_WRONLY;
	else
		flags = O_CREAT | O_EXCL | O_WRONLY;

	error = 0;
	if ((i = open(argv[1], flags, 0600)) != -1) {
		FILE *fp;

		fp = fdopen(i, "w");
		if (fp == NULL) {
			perror("fdopen");
			unlink(argv[1]);
			close(i);
			return (-1);
		}
		uef.uef_magic = HFS_EXTATTR_MAGIC;
		uef.uef_version = HFS_EXTATTR_VERSION;
		uef.uef_size = atoi(argv[0]);
		if (fwrite(&uef, sizeof(uef), 1, fp) != 1)
			error = -1;
		else if (fs_path) {
			if (verify_paths(fs_path, argv[1])) 
				usage();
			headersize = sizeof(struct hfs_extattr_header);
			chunksize = headersize + uef.uef_size;
			zero_buf = (char *) (malloc(chunksize));
			if (zero_buf == NULL) {
				perror("malloc");
				unlink(argv[1]);
				fclose(fp);
				return (-1);
			}
			memset(zero_buf, 0, chunksize);
			if (initial_value != NULL) {
				header.ueh_flags = HFS_EXTATTR_ATTR_FLAG_INUSE;

				/* Include the terminating NULL? */
				header.ueh_len = strlen(initial_value)+1;
				if (header.ueh_len > uef.uef_size)
					header.ueh_len = uef.uef_size;

				/* 
				 * The kernel doesn't know what to do with 
				 * HFS generation numbers either...
				 */
				header.ueh_i_gen = 0;

				memcpy(zero_buf, &header, headersize);
				strncpy((char *)(zero_buf+headersize), 
				    initial_value, uef.uef_size);
			}
			num_inodes = num_inodes_by_path(fs_path);
			for (loop = 0; loop < num_inodes; loop++) {
				error = fwrite(zero_buf, chunksize, 1, fp);
				if (error != 1) {
					perror("fwrite");
					unlink(argv[1]);
					fclose(fp);
					return (-1);
				}
			}
		}
		fclose(fp);
	}
	if (i == -1) {
		/* unable to open file */
		perror(argv[1]);
		return (-1);
	}
	if (error == -1) {
		perror(argv[1]);
		unlink(argv[1]);
		return (-1);
	}

	return (0);
}

int
showattr(int argc, char *argv[])
{
	struct hfs_extattr_fileheader	uef;
	int i, fd;

	if (argc != 1)
		usage();

	fd = open(argv[0], O_RDONLY);
	if (fd == -1) {
		perror(argv[0]);
		return (-1);
	}

	i = read(fd, &uef, sizeof(uef));
	if (i == -1) {
		perror(argv[0]);
		return (-1);
	}
	if (i != sizeof(uef)) {
		fprintf(stderr, "%s: invalid file header\n", argv[0]);
		return (-1);
	}

	if (uef.uef_magic != HFS_EXTATTR_MAGIC) {
		fprintf(stderr, "%s: bad magic\n", argv[0]);
		return (-1);
	}

	printf("%s: version %d, size %d\n", argv[0], uef.uef_version,
	    uef.uef_size);

	return (0);
}

int
main(int argc, char *argv[])
{
	int	error = 0, attrnamespace;

	if (argc < 2)
		usage();

#if 0
	/*
	 * XXXMAC/CDV: The start, stop, enable, and disable support is
	 * not yet present in the kernel, so disable them here until kernel
	 * support is present.
	 */
	if (!strcmp(argv[1], "start")) {
		if (argc != 3)
			usage();
		error = extattrctl(argv[2], HFS_EXTATTR_CMD_START, NULL, 0,
		    NULL);
		if (error) {
			perror("extattrctl start");
			return (-1);
		}
	} else if (!strcmp(argv[1], "stop")) {
		if (argc != 3)
			usage();
		error = extattrctl(argv[2], HFS_EXTATTR_CMD_STOP, NULL, 0,
		   NULL);
		if (error) {
			perror("extattrctl stop");
			return (-1);
		}
	} else if (!strcmp(argv[1], "enable")) {
		if (argc != 6)
			usage();
		error = extattr_string_to_namespace(argv[3], &attrnamespace);
		if (error) {
			perror("extattrctl enable");
			return (-1);
		}
		error = extattrctl(argv[2], HFS_EXTATTR_CMD_ENABLE, argv[5],
		    attrnamespace, argv[4]);
		if (error) {
			perror("extattrctl enable");
			return (-1);
		}
	} else if (!strcmp(argv[1], "disable")) {
		if (argc != 5)
			usage();
		error = extattr_string_to_namespace(argv[3], &attrnamespace);
		if (error) {
			perror("extattrctl disable");
			return (-1);
		}
		error = extattrctl(argv[2], HFS_EXTATTR_CMD_DISABLE, NULL,
		    attrnamespace, argv[4]);
		if (error) {
			perror("extattrctl disable");
			return (-1);
		}
	} else 
#endif /* 0 */
	if (!strcmp(argv[1], "initattr")) {
		argc -= 2;
		argv += 2;
		error = initattr(argc, argv);
		if (error)
			return (-1);
	} else if (!strcmp(argv[1], "showattr")) {
		argc -= 2;
		argv += 2;
		error = showattr(argc, argv);
		if (error)
			return (-1);
	} else
		usage();

	return (0);
}
