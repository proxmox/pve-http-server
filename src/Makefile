DESTDIR=
PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

all:

install: PVE
	install -d -m 755 ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/AnyEvent.pm ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/Formatter.pm ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/Utils.pm ${PERL5DIR}/PVE/APIServer
	install -d -m 755 ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Standard.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Bootstrap.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/HTML.pm ${PERL5DIR}/PVE/APIServer/Formatter

.PHONY: clean distclean
distclean: clean
	rm -f examples/simple-demo.pem

clean:
	rm -rf examples/simple-demo.lck
	find . -name '*~' -exec rm {} ';'
