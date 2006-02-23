/* TBD/CDV */
/* #ifdef CONFIG_SECURITY_SELINUX_DEVELOP */
int context_struct_to_string(context_struct_t * context,
			     security_context_t * scontext,
			     __u32 *scontext_len);

/* TBD/CDV extern int avc_debug_always_allow; */

static __inline int compute_sid_handle_invalid_context(
	context_struct_t *scontext,
	context_struct_t *tcontext,
	security_class_t tclass,
	context_struct_t *newcontext)
{
	security_context_t s, t, n;
	__u32 slen, tlen, nlen;

	if (avc_debug_always_allow) {
		context_struct_to_string(scontext, &s, &slen);
		context_struct_to_string(tcontext, &t, &tlen);
		context_struct_to_string(newcontext, &n, &nlen);
		printf("security_compute_sid:  invalid context %s", n);
		printf(" for scontext=%s", s);
		printf(" tcontext=%s", t);
		printf(" tclass=%s\n", policydb.p_class_val_to_name[tclass-1]);
		sebsd_free(s, M_SEBSD_SS);
		sebsd_free(t, M_SEBSD_SS);
		sebsd_free(n, M_SEBSD_SS);
		return 0;
	} else {
		return EACCES;
	}
}

static __inline int convert_context_handle_invalid_context(
	context_struct_t *context)
{
	security_context_t s;
	__u32 len;

	if (avc_debug_always_allow) {
		context_struct_to_string(context, &s, &len);
		printf("security:  context %s is invalid\n", s);
		sebsd_free(s, M_SEBSD_SS);
		return 0;
	} else {
		return EINVAL;
	}
}

/* TBD/CDV */
/* #else */
/* #define compute_sid_handle_invalid_context(scontext,tcontext,tclass,newcontext) EACCES */
/* #define convert_context_handle_invalid_context(context) EINVAL */
/* #endif */

#ifdef __FreeBSD__

#ifdef _KERNEL
struct sx;
struct sx policy_lock;
#define	POLICY_INIT		\
	SX_SYSINIT(policy_lock, &policy_lock, "SEBSD Policy Lock")
#define POLICY_RDLOCK 		sx_slock(&policy_lock)
#define POLICY_WRLOCK 		sx_xlock(&policy_lock)
#define POLICY_RDUNLOCK 	sx_sunlock(&policy_lock)
#define POLICY_WRUNLOCK 	sx_xunlock(&policy_lock)
#else
#define POLICY_RDLOCK
#define POLICY_WRLOCK
#define POLICY_RDUNLOCK
#define POLICY_WRUNLOCK
#endif

#ifdef _KERNEL
struct mtx;
struct mtx load_lock;
#define LOAD_INIT	\
	MTX_SYSINIT(load_lock, &load_lock, "SEBSD Load Lock", MTX_DEF)
#define LOAD_LOCK 	mtx_lock(&load_lock)
#define LOAD_UNLOCK	mtx_unlock(&load_lock)
#else
#define LOAD_LOCK 
#define LOAD_UNLOCK
#define INTERRUPTS_OFF 
#define INTERRUPTS_ON 
#endif

#else /* __FreeBSD__ */

#ifdef __KERNEL__
static DECLARE_MUTEX(policy_sem);
#define POLICY_RDLOCK safe_down(&policy_sem)
#define POLICY_WRLOCK safe_down(&policy_sem)
#define POLICY_RDUNLOCK safe_up(&policy_sem)
#define POLICY_WRUNLOCK safe_up(&policy_sem)
#else
#define POLICY_RDLOCK
#define POLICY_WRLOCK
#define POLICY_RDUNLOCK
#define POLICY_WRUNLOCK
#endif

#ifdef __KERNEL__
static DECLARE_MUTEX(load_sem);
#define LOAD_LOCK down(&load_sem)
#define LOAD_UNLOCK up(&load_sem)
#define INTERRUPTS_OFF local_irq_disable()
#define INTERRUPTS_ON local_irq_enable()
#else
#define LOAD_LOCK 
#define LOAD_UNLOCK
#define INTERRUPTS_OFF 
#define INTERRUPTS_ON 
#endif
#endif /* __FreeBSD__ */
