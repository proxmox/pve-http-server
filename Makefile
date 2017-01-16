PACKAGE=libpve-http-server-perl
PKGVER=1.0
PKGREL=1

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_all.deb

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/${PACKAGE}

WWWBASEDIR=${DESTDIR}/usr/share/${PACKAGE}
WWWCSSDIR=${WWWBASEDIR}/css
WWWFONTSDIR=${WWWBASEDIR}/fonts
WWWJSDIR=${WWWBASEDIR}/js

# bootstrap library
BTVER=3.3.7
BTDIR=bootstrap-${BTVER}-dist
BTSRC=${BTDIR}.zip

BTDATA = 							\
	${BTDIR}/css/bootstrap.min.css				\
	${BTDIR}/css/bootstrap-theme.min.css			\
	${BTDIR}/js/bootstrap.min.js				\
	${BTDIR}/fonts/glyphicons-halflings-regular.ttf

JQVER=3.3.1
JQSRC=jquery-${JQVER}.min.js

all:

.PHONY: deb
deb ${DEB}:
	rm -rf build
	rsync -a * build
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

download_bootstrap:
	rm -f ${BTSRC}$ ${BTSRC}.tmp
	wget https://github.com/twbs/bootstrap/releases/download/v${BTVER}/${BTSRC} -O ${BTSRC}.tmp
	mv ${BTSRC}.tmp ${BTSRC}

download_jquery:
	rm -f ${JQSRC} ${JQSRC}.tmp
	wget https://code.jquery.com/jquery-3.1.1.min.js -O ${JQSRC}.tmp
	mv ${JQSRC}.tmp ${JQSRC}

${BTDATA}: ${BTSRC}
	rm -rf ${BTDIR}
	unzip -x ${BTSRC}
	touch $@

install: ${BTDATA}
	install -d -m 755 ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/AnyEvent.pm ${PERL5DIR}/PVE/APIServer
	install -m 0644 PVE/APIServer/Formatter.pm ${PERL5DIR}/PVE/APIServer
	install -d -m 755 ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Standard.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/Bootstrap.pm ${PERL5DIR}/PVE/APIServer/Formatter
	install -m 0644 PVE/APIServer/Formatter/HTML.pm ${PERL5DIR}/PVE/APIServer/Formatter
	# install bootstrap and jquery
	install -d -m 755 ${WWWBASEDIR}
	install -d -m 755 ${WWWCSSDIR}
	install -m 0644 -o www-data -g www-data ${BTDIR}/css/bootstrap.min.css ${WWWCSSDIR}
	install -m 0644 -o www-data -g www-data ${BTDIR}/css/bootstrap-theme.min.css ${WWWCSSDIR}
	install -d -m 755 ${WWWJSDIR}
	install -m 0644 -o www-data -g www-data ${BTDIR}/js/bootstrap.min.js ${WWWJSDIR}
	install -m 0644 -o www-data -g www-data ${JQSRC} ${WWWJSDIR}
	install -d -m 755 ${WWWFONTSDIR}
	install -m 0644 ${BTDIR}/fonts/glyphicons-halflings-regular.ttf ${WWWFONTSDIR}


.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

distclean: clean

clean:
	rm -rf ./build *.deb *.changes ${BTDIR} simple-demo.pem simple-demo.lck
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}
