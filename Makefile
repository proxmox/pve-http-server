include /usr/share/dpkg/pkg-info.mk

PACKAGE=libpve-http-server-perl

GITVERSION:=$(shell git rev-parse HEAD)
BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

all:

.PHONY: deb
deb: ${DEB}
${DEB}:
	rm -rf ${BUILDDIR}
	rsync -a * ${BUILDDIR}
	echo "git clone git://git.proxmox.com/git/pve-http-server\\ngit checkout $(GITVERSION)" > $(BUILDDIR)/debian/SOURCE
	cd ${BUILDDIR}; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

install: PVE
	install -d -m 755 ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/AnyEvent.pm ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/Formatter.pm ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/Utils.pm ${PERL5DIR}/PVE/APIServer
	install -d -m 755 ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Standard.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Bootstrap.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/HTML.pm ${PERL5DIR}/PVE/APIServer/Formatter

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh -X repoman@repo.proxmox.com -- upload --product pve,pmg --dist buster

.PHONY: clean distclean
distclean: clean
	rm -f examples/simple-demo.pem

clean:
	rm -rf ${PACKAGE}-*/ *.deb *.changes *.buildinfo ${BTDIR} examples/simple-demo.lck
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
