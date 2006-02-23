
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* FLASK */

/*
 * A symbol table (symtab) maintains associations between symbol
 * strings and datum values.  The type of the datum values
 * is arbitrary.  The symbol table type is implemented
 * using the hash table type (hashtab).
 */ 

#ifndef _SYMTAB_H_
#define _SYMTAB_H_

#include <sepol/hashtab.h>

typedef struct {
	hashtab_t table;	/* hash table (keyed on a string) */
	uint32_t nprim;		/* number of primary names in table */
} symtab_t;

int symtab_init(symtab_t *, unsigned int size);

#endif	/* _SYMTAB_H_ */

/* FLASK */

