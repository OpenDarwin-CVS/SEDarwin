/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * $FreeBSD$
 */

#ifndef _SYS_SECURITY_LINUX_COMPAT_H
#define _SYS_SECURITY_LINUX_COMPAT_H

/*
 * Try and convert some of the linux kernel routines to something that
 * works in Darwin.  Perhaps a bit dangerous, but the hope is that
 * diffs to the SELinux tree will be quite a bit smaller.
 */

#include <sys/types.h>			/* NOTE: mach sys/types, not BSD one. */
#include <machine/endian.h>		/* We need to explicitly include */
#include <architecture/byte_order.h>	/* byte order includes for mach. */

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t  u8;


#if !defined(BYTE_ORDER)
#error BYTE_ORDER not defined
#elif BYTE_ORDER == LITTLE_ENDIAN
#define	cpu_to_le32(x)	((__uint32_t)(x))
#define	cpu_to_le64(x)	((__uint64_t)(x))
#define	le32_to_cpu(x)	((__uint32_t)(x))
#define	le64_to_cpu(x)	((__uint64_t)(x))
#elif BYTE_ORDER == BIG_ENDIAN
#define	cpu_to_le32(x)	NXSwapHostLongToLittle(x)
#define	cpu_to_le64(x)	NXSwapHostLongLongToLittle(x)
#define	le32_to_cpu(x)	NXSwapLittleLongToHost(x)
#define	le64_to_cpu(x)	NXSwapLittleLongLongToHost(x)
#else
#error unsupported BYTE_ORDER
#endif /* BYTE_ORDER */

#if !defined(_KERNEL) && !defined(KERNEL)

/* sedarwin uses same ss source files for userspace */
#define kmalloc(size,flags) malloc(size)
#define kfree(v) free(v)
#define __get_free_page(flags) malloc(PAGE_SIZE)
#define GFP_ATOMIC  1
#define GFP_KERNEL  2

#else /* _KERNEL */

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define __init

extern void *sebsd_malloc(size_t size, int type, int flags);
extern void sebsd_free(void *, int);

/* BSD-style malloc/free emulation */
#ifndef M_SEBSD
#include <sys/malloc.h>
#define M_SEBSD				M_MACTEMP
#endif

/* Linux-style kmalloc/kfree (note kfree namespace collision) */
#define kmalloc(size, flags)		sebsd_malloc(size, M_SEBSD, flags)
#define kfree(addr)			sebsd_free(addr, M_SEBSD)
#define __get_free_page(flags)		sebsd_malloc(PAGE_SIZE, M_SEBSD, flags) 
#define GFP_ATOMIC  M_WAITOK		/* XXX - want M_NOWAIT but too early */
#define GFP_KERNEL  M_WAITOK

/* TBD: no boot-time tunable support yet */
#define TUNABLE_INT_FETCH(str,var)

/* spinlock */
#define spinlock_t mutex_t *
#define spin_lock_irqsave(m,flags)	mutex_lock(*(m))
#define spin_unlock_irqrestore(m,flags)	mutex_unlock(*(m))

/* emulate linux audit support */
struct audit_buffer;
struct audit_buffer *audit_log_start(void);
void audit_log(const char *, ...);
void audit_log_end(struct audit_buffer *);
void audit_log_format(struct audit_buffer *, const char *, ...);   
void audit_log_untrustedstring(struct audit_buffer *, const char *);

#endif /* _KERNEL */

#define BUG() printf("BUG: %s:%d", __FILE__, __LINE__)
#define BUG_ON(x) do { if (x) BUG(); } while(0)

#define wmb() 

/* printk */
#ifdef MACH_KDB
#define printk kprintf
#else
#define printk printf
#endif
#define KERN_WARNING "warning: "
#define KERN_INFO
#define KERN_ERR     "error: "

#endif /* _SYS_SECURITY_LINUX_COMPAT_H */
