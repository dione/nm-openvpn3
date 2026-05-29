# Canonical install path for the nm-openvpn3 NM VPN plugin (Rust
# workspace).  Packagers call `make install DESTDIR=...` against a
# staging tree; debian/rules and any RPM spec layer their multiarch
# library directory + offline cargo flags on top via variable overrides.
#
# scripts/install-test.sh remains the dev-workstation smoke-test path
# — it wraps this Makefile with sudo + NetworkManager / dbus reloads.
#
# Overridable variables (envoritonment or `make var=value`):
#   prefix, libdir, libexecdir, pluginlibdir, namedir, localedir,
#   dbusconfdir, metainfodir, DESTDIR, CARGO, CARGO_FLAGS, MSGFMT

CARGO        ?= cargo
CARGO_FLAGS  ?= --release --workspace

DESTDIR      ?=
prefix       ?= /usr
libdir       ?= $(prefix)/lib
libexecdir   ?= $(prefix)/libexec
pluginlibdir ?= $(libdir)/NetworkManager
# NetworkManager scans VPN .name files from the non-multiarch
# /usr/lib/NetworkManager/VPN directory only — every Debian VPN plugin
# (nm-openvpn, nm-pptp, nm-vpnc, …) installs there, and the multiarch
# path is searched for the cdylib referenced from `plugin=` inside the
# .name file but NOT for the .name file itself.  Hard-code the non-
# multiarch path so a packager who overrides `libdir` to the multiarch
# directory still lands the .name in the spot NM looks at.
namedir      ?= /usr/lib/NetworkManager/VPN
localedir    ?= $(prefix)/share/locale
dbusconfdir  ?= $(prefix)/share/dbus-1/system.d
metainfodir  ?= $(prefix)/share/metainfo

INSTALL      ?= install
INSTALL_DATA ?= $(INSTALL) -m 0644
INSTALL_BIN  ?= $(INSTALL) -m 0755
MSGFMT       ?= msgfmt
XGETTEXT     ?= xgettext

POT          := po/nm-openvpn3.pot
POTFILES     := po/POTFILES.in

TARGET_DIR   ?= target/release
SERVICE_BIN  := $(TARGET_DIR)/nm-openvpn3-service
AUTH_BIN     := $(TARGET_DIR)/nm-openvpn3-auth-dialog
# Cargo prefixes "lib" + replaces "-" with "_" on the cdylib filename;
# NM expects the dashed form per [libnm]/[GNOME] keys in the .name file,
# so the install step renames both libraries.
PROP_LIB     := $(TARGET_DIR)/libnm_vpn_plugin_openvpn3.so
EDIT_LIB     := $(TARGET_DIR)/libnm_vpn_plugin_openvpn3_editor.so
NAME_IN      := data/NetworkManager-VPN/nm-openvpn3-service.name.in
DBUS_CONF    := data/dbus-1/nm-openvpn3-service.conf
METAINFO_IN  := appdata/network-manager-openvpn3.metainfo.xml.in

PO_FILES     := $(wildcard po/*.po)
MO_FILES     := $(PO_FILES:po/%.po=po/%.mo)

.PHONY: all build install install-core install-gnome install-i18n \
        check clean pot

all: build

build:
	$(CARGO) build $(CARGO_FLAGS)

# `install` lays down both binary-package payloads under DESTDIR; the
# debian/rules `*.install` globs split the staged tree into the core +
# gnome packages.  Split targets stay public so packagers building a
# core-only image can skip the GTK side.
install: install-core install-gnome install-i18n

install-core:
	$(INSTALL) -d $(DESTDIR)$(libexecdir)
	$(INSTALL_BIN) $(SERVICE_BIN) $(DESTDIR)$(libexecdir)/nm-openvpn3-service
	$(INSTALL_BIN) $(AUTH_BIN)    $(DESTDIR)$(libexecdir)/nm-openvpn3-auth-dialog
	$(INSTALL) -d $(DESTDIR)$(namedir)
	sed -e 's|@LIBEXECDIR@|$(libexecdir)|g' \
	    -e 's|@PLUGINDIR@|$(pluginlibdir)|g' \
	    $(NAME_IN) > $(DESTDIR)$(namedir)/nm-openvpn3-service.name
	chmod 0644 $(DESTDIR)$(namedir)/nm-openvpn3-service.name
	$(INSTALL) -d $(DESTDIR)$(dbusconfdir)
	$(INSTALL_DATA) $(DBUS_CONF) $(DESTDIR)$(dbusconfdir)/nm-openvpn3-service.conf

install-gnome:
	$(INSTALL) -d $(DESTDIR)$(pluginlibdir)
	$(INSTALL_DATA) $(PROP_LIB) $(DESTDIR)$(pluginlibdir)/libnm-vpn-plugin-openvpn3.so
	$(INSTALL_DATA) $(EDIT_LIB) $(DESTDIR)$(pluginlibdir)/libnm-vpn-plugin-openvpn3-editor.so
	$(INSTALL) -d $(DESTDIR)$(metainfodir)
	$(INSTALL_DATA) $(METAINFO_IN) \
	    $(DESTDIR)$(metainfodir)/network-manager-openvpn3.metainfo.xml

# msgfmt'd catalogs live under po/ so debian/rules can build them
# without touching the cargo target/ tree.
%.mo: %.po
	$(MSGFMT) -o $@ $<

install-i18n: $(MO_FILES)
	@set -e; for mo in $(MO_FILES); do \
	    lang=$$(basename $$mo .mo); \
	    dir=$(DESTDIR)$(localedir)/$$lang/LC_MESSAGES; \
	    $(INSTALL) -d $$dir; \
	    $(INSTALL_DATA) $$mo $$dir/nm-openvpn3.mo; \
	done

# Regenerate the translation template from the sources listed in
# po/POTFILES.in.  xgettext's C parser handles Rust string literals and
# spans multi-line tr(...) / gettext(...) calls, so it extracts the
# editor's wrapped strings reliably.  Run after adding/changing any
# user-visible string, then `msgmerge` the .po catalogs.
pot:
	$(XGETTEXT) --files-from=$(POTFILES) --from-code=UTF-8 \
	    --language=C --keyword=tr --keyword=gettext --keyword=ngettext:1,2 \
	    --package-name=nm-openvpn3 --copyright-holder='nm-openvpn3 contributors' \
	    --output=$(POT)

check:
	$(CARGO) test $(CARGO_FLAGS)

clean:
	$(CARGO) clean
	rm -f $(MO_FILES)
