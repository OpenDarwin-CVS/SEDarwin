/*-
 * Copyright (c) 2001 Robert N. M. Watson
 * All rights reserved.
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
 */
/*
 * TrustedBSD: Utility functions for extended attributes.
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/extattr.h>
#include <errno.h>
#include <string.h>

int
extattr_namespace_to_string(int attrnamespace, char **string)
{

	switch(attrnamespace) {
	case EXTATTR_NAMESPACE_USER:
		if (string != NULL)
			*string = strdup(EXTATTR_NAMESPACE_USER_STRING);
		return (0);

	case EXTATTR_NAMESPACE_SYSTEM:
		if (string != NULL)
			*string = strdup(EXTATTR_NAMESPACE_SYSTEM_STRING);
		return (0);

	default:
		errno = EINVAL;
		return (-1);
	}
}

int
extattr_string_to_namespace(const char *string, int *attrnamespace)
{

	if (!strcmp(string, EXTATTR_NAMESPACE_USER_STRING)) {
		if (attrnamespace != NULL)
			*attrnamespace = EXTATTR_NAMESPACE_USER;
		return (0);
	} else if (!strcmp(string, EXTATTR_NAMESPACE_SYSTEM_STRING)) {
		if (attrnamespace != NULL)
			*attrnamespace = EXTATTR_NAMESPACE_SYSTEM;
		return (0);
	} else {
		errno = EINVAL;
		return (-1);
	}
}

int
extattrctl(const char *_path, int _cmd, const char *_filename,
    int _attrnamespace, const char *_attrname)
{

	return (syscall(SYS_extattrctl, _path, _cmd, _filename, _attrnamespace,
	    _attrname));
}

int
extattr_delete_fd(int _fd, int _attrnamespace, const char *_attrname)
{

	return (syscall(SYS_extattr_delete_fd, _fd, _attrnamespace,
	    _attrname));
}

int
extattr_delete_file(const char *_path, int _attrnamespace,
    const char *_attrname)
{

	return (syscall(SYS_extattr_delete_file, _path, _attrnamespace,
	    _attrname));
}

int
extattr_delete_link(const char *_path, int _attrnamespace,
    const char *_attrname)
{

	return (syscall(SYS_extattr_delete_link, _path, _attrnamespace,
	    _attrname));
}

ssize_t
extattr_get_fd(int _fd, int _attrnamespace, const char *_attrname,
    void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_get_fd, _fd, _attrnamespace, _attrname,
	    _data, _nbytes));
}

ssize_t
extattr_get_file(const char *_path, int _attrnamespace,
    const char *_attrname, void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_get_file, _path, _attrnamespace, _attrname,
	    _data, _nbytes));
}

ssize_t
extattr_get_link(const char *_path, int _attrnamespace,
    const char *_attrname, void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_get_link, _path, _attrnamespace, _attrname,
	    _data, _nbytes));
}

int
extattr_set_fd(int _fd, int _attrnamespace, const char *_attrname,
    const void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_set_fd, _fd, _attrnamespace, _attrname,
	    _data, _nbytes));
}

int
extattr_set_file(const char *_path, int _attrnamespace, const char *_attrname,
    const void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_set_file, _path, _attrnamespace, _attrname,
	    _data, _nbytes));
}

int
extattr_set_link(const char *_path, int _attrnamespace, const char *_attrname,
    const void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_set_link, _path, _attrnamespace, _attrname,
	    _data, _nbytes));
}

ssize_t
extattr_list_file(const char *_path, int _attrnamespace, void *_data,
    size_t _nbytes)
{

	return (syscall(SYS_extattr_list_file, _path, _attrnamespace, _data,
	    _nbytes));
}

ssize_t
extattr_list_link(const char *_path, int _attrnamespace, void *_data, 
    size_t _nbytes)
{

	return (syscall(SYS_extattr_list_link, _path, _attrnamespace, _data,
	    _nbytes));
}

ssize_t
extattr_list_fd(int fd, int _attrnamespace, void *_data, size_t _nbytes)
{

	return (syscall(SYS_extattr_list_fd, fd, _attrnamespace, _data,
	    _nbytes));
}
