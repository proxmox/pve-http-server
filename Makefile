include /usr/share/dpkg/pkg-info.mk

PACKAGE=libpve-http-server-perl

GITVERSION:=$(shell git rev-parse HEAD)
BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION_UPSTREAM)

DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_all.deb

all:

.PHONY: deb
deb: $(DEB)
$(DEB):
	rm -rf $(BUILDDIR)
	cp -a src $(BUILDDIR)
	cp -a debian $(BUILDDIR)/
	echo "git clone git://git.proxmox.com/git/pve-http-server\\ngit checkout $(GITVERSION)" > $(BUILDDIR)/debian/SOURCE
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: upload
upload: $(DEB)
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com -- upload --product pve,pmg --dist bullseye

.PHONY: clean distclean
distclean: clean
	$(MAKE) -C src $@

clean:
	$(MAKE) -C src $@
	rm -rf $(PACKAGE)-*/ *.deb *.changes *.buildinfo $(BTDIR) examples/simple-demo.lck

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)
