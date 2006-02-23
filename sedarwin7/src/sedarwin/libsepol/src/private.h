/* Private definitions for libsepol. */

/* Endian conversion for reading and writing binary policies */

#include <sys/types.h>
#include <sys/endian.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define	cpu_to_le32(x)	((__uint32_t)(x))
#define	cpu_to_le64(x)	((__uint64_t)(x))
#define	le32_to_cpu(x)	((__uint32_t)(x))
#define	le64_to_cpu(x)	((__uint64_t)(x))
#else /* BYTE_ORDER != LITTLE_ENDIAN */
#define	cpu_to_le32(x)	bswap32((x))
#define	cpu_to_le64(x)	bswap64((x))
#define	le32_to_cpu(x)	bswap32((x))
#define	le64_to_cpu(x)	bswap64((x))
#endif /* BYTE_ORDER */

/* Policy compatibility information. */
struct policydb_compat_info {
	int version;
	int sym_num;
	int ocon_num;
};

extern struct policydb_compat_info policydb_compat[];
extern struct policydb_compat_info *policydb_lookup_compat(int version);

/* Reading from a policy "file". */
static inline void *next_entry(struct policy_file * fp, size_t bytes)
{
	static unsigned char buffer[BUFSIZ];
	size_t nread;

	if (bytes > sizeof buffer)
		return NULL;

	switch (fp->type) {
	case PF_USE_STDIO:
		nread = fread(buffer, bytes, 1, fp->fp);
		if (nread != bytes)
			return NULL;
		break;
	case PF_USE_MEMORY:
		if (bytes > fp->len) 
			return NULL;
		memcpy(buffer, fp->data, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		break;
	default:
		return NULL;
	}
	return buffer;
}

