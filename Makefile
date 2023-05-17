include /usr/share/dpkg/pkg-info.mk

PACKAGE=libpve-http-server-perl

GITVERSION:=$(shell git rev-parse HEAD)
BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION)

DSC=$(PACKAGE)_$(DEB_VERSION).dsc
DEB=$(PACKAGE)_$(DEB_VERSION)_all.deb

all:

$(BUILDDIR): src debian
	rm -rf $@ $@.tmp
	cp -a src $@.tmp
	cp -a debian $@.tmp/
	echo "git clone git://git.proxmox.com/git/pve-http-server\\ngit checkout $(GITVERSION)" > $@.tmp/debian/SOURCE
	mv $@.tmp $@

.PHONY: deb
deb: $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: dsc
dsc: $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc
	lintian $(DSC)

sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEB)
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com -- upload --product pve,pmg --dist $(UPLOAD_DIST)

.PHONY: clean distclean
distclean: clean
	$(MAKE) -C src $@

clean:
	$(MAKE) -C src $@
	rm -rf $(PACKAGE)-*/ *.deb *.dsc *.tar.* *.changes *.buildinfo examples/simple-demo.lck

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)
