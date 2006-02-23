
#include <machine/endian.h>
#include <architecture/byte_order.h>

#define	bswap32(x)	NXSwapLittleLongToHost(x)
#define	bswap64(x)	NXSwapLittleLongLongToHost(x)

