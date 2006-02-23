POLICY=		stacktrace
POLICY_VER=	1.0
POLICY_COMPVER=	1.0
POLICY_DESC=	"Stacktrace module"
POLICY_SRCS=	mac_stacktrace.c
POLICY_NOMAN=	yes

CFLAGS=-I.. -Wall

include ../../Makeconfig
include $(DARWIN_ROOT)/build/PolicyKext.mk

CLEANFILES	+=	trace.in stubs.in policy_ops.in policy.in \
			funcnames.in

update: mac_stacktrace.c.in trace.in stubs.in policy_ops.in
	@echo Updating mac_stacktrace.c...
	@cpp -U__APPLE_CC__ -C -P mac_stacktrace.c.in \
		| sed -e 's/^@@@/#/g' \
		| grep -v ^#pragma \
		> mac_stacktrace.c

policy.in: $(EXPORT_HDRS)/bsd/sys/mac_policy.h
	@cpp -P $< \
		| grep -v ^\$ \
		| awk 'RS=";" { if ($$1 == "typedef") { print $$0";" } }' \
		| tr -d "\n\t" \
		| tr ";" "\n" \
		| sed	-e 's/typedef //g' \
			-e 's/,/, /g' \
			-e 's/_t(/ (/g' \
			-e 's/ mpo_/ /g' \
		> $@

stubs.in: policy.in
	@cat $< \
		| grep -v init_bsd \
		| grep -v syscall \
		| awk -f mk_stubs.awk \
		> $@

trace.in: policy.in
	@cat $< \
		| grep -v syscall \
		| awk -f mk_trace.awk \
		> $@

funcnames.in: policy.in
	@cat $< \
		| grep -v syscall \
		| awk '{if (NR != 1) { printf ",\n" } printf "\t\"" $$2 "\""}' \
		> $@

policy_ops.in: policy.in
	@cat $< \
		| awk -f mk_policy_ops.awk \
		> $@
