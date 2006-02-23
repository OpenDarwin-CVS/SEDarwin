#-
# Copyright (c) 2005 SPARTA, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#                                      
CFLAGS=
MIGDIR = /usr/bin
MIGSOURCE = /usr/include

all: mclient mserver

mserver: mserver.o mtests.o
	cc -o $@ $^ /usr/lib/libmac.a

mclient: mclient.o mtestu.o
	cc -o $@ $^

mclient.c: mtestu.h
mserver.c: mtestu.h

mtest%.c: mtest.defs
	sh $(MIGDIR)/mig -migcom /usr/libexec/migcom -user mtestu.c -server mtests.c -header mtestu.h -sheader mtests.h -flasksc mtest.flask $<

mtest%.h: mtest.defs
	sh $(MIGDIR)/mig -migcom /usr/libexec/migcom -I$(MIGSOURCE) -user mtestu.c -server mtests.c -header mtestu.h -sheader mtests.h -flasksc mtest.flask $<
$<

VPATH = $(MIGSOURCE)/mach

#%.flask: %.defs:
#	sh $(MIGDIR)/mig -migcom /usr/libexec/migcom -I$(MIGSOURCE) -user /dev/null -server /dev/null -header /dev/null -sheader /dev/null -flasksc $@ $<

kernel.flask:
	rm -f $@
	for i in $(MIGSOURCE)/mach/*.defs; do sh $(MIGDIR)/mig -migcom /usr/libexec/migcom -I$(MIGSOURCE) -user /dev/null -server /dev/null -header /dev/null -sheader /dev/null -flasksc `basename $$i .defs`.flask $$i; cat `basename $$i .defs`.flask >> $@; done

clean:
	rm -f *.o mtest[su].[ch] mtest.flask mserver mclient

.PRECIOUS: mtests.c mtests.h mtestu.c mtestu.h
