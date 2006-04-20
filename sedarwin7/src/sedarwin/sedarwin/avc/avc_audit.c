/*-
 * Copyright (c) 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS"). 
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <stdarg.h>

#include <kern/lock.h>

#include <sedarwin/linux-compat.h>
#include <sedarwin/sebsd.h>

/*
 * Emulate Linux audit API.
 * In the future we may wish to use the BSD audit support instead.
 * TBD: use a freelist so we don't have to mallc/free so much.
 */

mutex_t *avc_log_lock;

extern void conslog_putc(char);

struct audit_buffer {
	struct sbuf sbuf;
	char buf[1024];
};

struct audit_buffer *
audit_log_start(void)
{
	struct audit_buffer *ab;

	ab = sebsd_malloc(sizeof(*ab), M_SEBSD, M_NOWAIT);
	if (ab == NULL) {
		printf("%s: unable to allocate audit buffer\n", __func__);
		return (NULL);
	}
	sbuf_new(&ab->sbuf, ab->buf, sizeof(ab->buf), SBUF_FIXEDLEN);
	return (ab);
}

void
audit_log_end(struct audit_buffer *ab)
{

	sbuf_finish(&ab->sbuf);
	mutex_lock(avc_log_lock);
	printf("\n%s\n", sbuf_data(&ab->sbuf));
	mutex_unlock(avc_log_lock);
	sbuf_delete(&ab->sbuf);
	sebsd_free(ab, M_SEBSD);
}

void
audit_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	mutex_lock(avc_log_lock);
	_doprnt(fmt, &ap, conslog_putc, 10);
	printf("\n");
	mutex_unlock(avc_log_lock);
	va_end(ap);
}

void
audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbuf_vprintf(&ab->sbuf, fmt, ap);
	va_end(ap);
}

void
audit_log_untrustedstring(struct audit_buffer *ab, const char *s)
{

	sbuf_cat(&ab->sbuf, s);
}
