#ifndef _SEPOL_HANDLE_H_
#define _SEPOL_HANDLE_H_

struct sepol_handle;
typedef struct sepol_handle sepol_handle_t;

/* Create and return a sepol handle. */
sepol_handle_t *sepol_handle_create(void);

/* Destroy a sepol handle. */
void sepol_handle_destroy(sepol_handle_t *);

#endif
