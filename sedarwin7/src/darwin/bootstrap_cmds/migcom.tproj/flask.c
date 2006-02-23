/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
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

#include <assert.h>
#include <stdlib.h>

#include <mach/message.h>
#include "write.h"
#include "utils.h"
#include "global.h"
#include "error.h"

void
WriteFlaskSecClass(FILE *file, statement_t *stats)
{
	int          i, maxrt = 0;
    statement_t *stat;
    routine_t   *routines[128];

    memset(routines, 0, sizeof (routines));

    fprintf(file, "class mi_%s #subsystem %d\n{\n", SubsystemName,
	SubsystemBase);

    for (stat = stats; stat != stNULL; stat = stat->stNext)
       if (stat->stKind == skRoutine) {
	    if (stat->stRoutine->rtNumber >= 0 &&
		stat->stRoutine->rtNumber < 128) {
		routines[stat->stRoutine->rtNumber] = stat->stRoutine;
		if (maxrt < stat->stRoutine->rtNumber)
		    maxrt = stat->stRoutine->rtNumber;
	    }
	    else
		fprintf(stderr, "unexpected routine number %d\n", stat->stRoutine->rtNumber);
       }

    for (i = 0; i <= maxrt; i++)
        if (routines[i])
	    fprintf(file, "\t%s\n", routines[i]->rtName);
	else
	    fprintf(file, "\t_unused%d\n", i);

    fprintf(file, "}\n");
}
