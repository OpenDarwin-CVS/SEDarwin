#ifndef _SEPOL_INTERNAL_DEBUG_H_
#define _SEPOL_INTERNAL_DEBUG_H_

#include <stdio.h>
#include <sepol/debug.h>
#include "dso.h"
#include "handle.h"

#define STATUS_SUCCESS 0
#define STATUS_ERR -1
#define STATUS_NODATA 1

#define msg_write(handle_arg, level_arg,			   \
		  channel_arg, func_arg, ...) do {		   \
		sepol_handle_t *h = (handle_arg) ?: &sepol_compat_handle; \
		if (h->msg_callback) {				   \
			h->msg_fname = func_arg;		   \
			h->msg_channel = channel_arg;		   \
			h->msg_level = level_arg;		   \
								   \
			h->msg_callback(			   \
				h->msg_callback_arg,		   \
				h, __VA_ARGS__);		   \
		}                                                  \
	} while(0)

#define ERR(handle, ...) \
	msg_write(handle, SEPOL_MSG_ERR, "libsepol", \
	__FUNCTION__, __VA_ARGS__)

#define INFO(handle, ...) \
	msg_write(handle, SEPOL_MSG_INFO, "libsepol", \
	__FUNCTION__, __VA_ARGS__)

#define WARN(handle, ...) \
	msg_write(handle, SEPOL_MSG_WARN, "libsepol", \
	__FUNCTION__, __VA_ARGS__)

#ifdef __GNUC__
__attribute__ ((format (printf, 3, 4)))
#endif
extern void hidden sepol_msg_default_handler(
	void* varg,
	sepol_handle_t* msg,
	const char* fmt,
	...);

extern struct sepol_handle sepol_compat_handle;

hidden_proto(sepol_msg_get_channel)
hidden_proto(sepol_msg_get_fname)
hidden_proto(sepol_msg_get_level)

#endif 
