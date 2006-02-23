POLICY=		count
POLICY_VER=	1.0
POLICY_COMPVER=	1.0
POLICY_DESC=	"Entry Point Counter"
POLICY_SRCS=	mac_count.c
POLICY_NOMAN=	yes

include ../Makeconfig
include $(DARWIN_ROOT)/build/PolicyKext.mk

CLEANFILES+=	count_decls.h count_reg.h count_funcs.h count_policy_ops.h \
		policy.in

mac_count.c: count_decls.h count_reg.h count_funcs.h count_policy_ops.h

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

count_decls.h: policy.in
	@cat $< \
		| grep -v \
			-e ' destroy ' \
			-e ' init_bsd ' \
			-e ' init ' \
		| awk -f mk_count_decls.awk \
		> $@

count_reg.h: policy.in
	@cat $< \
		| grep -v \
			-e ' destroy ' \
			-e ' init_bsd ' \
			-e ' init ' \
		| awk -f mk_count_reg.awk \
		> $@

count_funcs.h: policy.in
	@cat $< \
		| grep -v \
			-e ' destroy ' \
			-e ' init_bsd ' \
			-e ' init ' \
		| awk -f mk_count_funcs.awk \
		> $@

count_policy_ops.h: policy.in
	@cat $< \
		| awk -f mk_count_policy_ops.awk \
		> $@
