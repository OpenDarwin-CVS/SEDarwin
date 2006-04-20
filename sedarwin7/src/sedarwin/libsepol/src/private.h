/* Private definitions for libsepol. */

/* Endian conversion for reading and writing binary policies */

#include <sys/types.h>
#include <machine/endian.h>
#include <sepol/policydb/policydb.h>
#include <architecture/byte_order.h>

typedef uint16_t __uint16_t;
typedef uint32_t __uint32_t;
typedef uint64_t __uint64_t;

#if BYTE_ORDER == LITTLE_ENDIAN
#define cpu_to_le16(x) ((__uint16_t) x)
#define le16_to_cpu(x) ((__uint16_t) x)
#define cpu_to_le32(x) ((__uint32_t) x)
#define le32_to_cpu(x) ((__uint32_t) x)
#define cpu_to_le64(x) ((__uint64_t) x)
#define le64_to_cpu(x) ((__uint64_t) x)
#else
#define cpu_to_le16(x)  OSSwapInt16(x)
#define cpu_to_le32(x)  OSSwapInt32(x)
#define cpu_to_le64(x)  OSSwapInt64(x)
#define le16_to_cpu(x)  OSSwapInt16(x)
#define le32_to_cpu(x)  OSSwapInt32(x)
#define le64_to_cpu(x)  OSSwapInt64(x)
#endif

/* Policy compatibility information. */
struct policydb_compat_info {
	unsigned int type;
        unsigned int version;
	unsigned int sym_num;
	unsigned int ocon_num;
};

extern struct policydb_compat_info *policydb_lookup_compat(unsigned int version, unsigned int type);

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
		if (nread != 1)
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

static inline size_t put_entry(const void *ptr, size_t size, size_t n, struct policy_file *fp)
{
	size_t bytes = size * n;

	switch (fp->type) {
	case PF_USE_STDIO:
		return fwrite(ptr, size, n, fp->fp);
	case PF_USE_MEMORY:
		if (bytes > fp->len) {
			errno = ENOSPC;
			return 0;
		}

		memcpy(fp->data, ptr, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		return n;
	case PF_LEN:
		fp->len += bytes;
		return n;
	default:
		return 0;
	}
	return 0;
}

