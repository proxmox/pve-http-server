PACKAGE=libpve-http-server-perl
PKGVER=1.0
PKGREL=1

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

all: ${DEB}

.PHONY: deb
deb ${DEB}:
	rm -rf build
	rsync -a debian build
	make DESTDIR=./build install
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}

install:
	install -d -m 755 ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/AnyEvent.pm ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/Formatter.pm ${PERL5DIR}/PVE/APIServer
	install -d -m 755 ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Standard.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Bootstrap.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/HTML.pm ${PERL5DIR}/PVE/APIServer/Formatter


.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
