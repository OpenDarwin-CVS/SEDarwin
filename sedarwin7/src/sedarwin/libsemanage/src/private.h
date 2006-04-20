/* Private definitions for libsemod. */

/* Endian conversion for reading and writing binary policies */

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* Read from a policy "file" and return a pointer to the requested set
   of bytes.  Do *NOT* free the returned pointer.  Returns NULL if the
   requested number of bytes is larger than the read buffer or if an
   I/O error occurred.  Note that this function is thread-safe. */
static inline void *next_entry(struct policy_file * fp, size_t bytes)
{
	size_t nread;

	if (bytes > sizeof (fp->buffer))
		return NULL;

	switch (fp->type) {
	case PF_USE_STDIO:
		nread = fread(fp->buffer, bytes, 1, fp->fp);
		if (nread != 1)
			return NULL;
		break;
	case PF_USE_MEMORY:
		if (bytes > fp->len) 
			return NULL;
		memcpy(fp->buffer, fp->data, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		break;
	default:
		return NULL;
	}
	return fp->buffer;
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
	default:
		return 0;
	}
	return 0;
}

