include ../../Makeconfig

ETCFILES= mac.conf
INSTALL= install

all:

install:
	cd ${CURDIR}; \
		${INSTALL} -o ${BINOWN} -g ${BINGRP} -m 644 \
		    $(ETCFILES) ${DESTDIR}/private/etc; \
		${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 755 ${DESTDIR}/private/etc/pam.d; \
		${INSTALL} -o ${BINOWN} -g ${BINGRP} -m 444 ../pam/pam.d/login \
		    ${DESTDIR}/private/etc/pam.d/login.sedarwin; \
		${INSTALL} -o ${BINOWN} -g ${BINGRP} -m 444 ../pam/pam.d/sshd \
		    ${DESTDIR}/private/etc/pam.d/sshd.sedarwin;

clean:
