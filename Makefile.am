bin_PROGRAMS = wd-security
wd_security_SOURCES = wd-security-cli.c wd-security.c encoding.c compat.c
wd_security_SOURCES += compat.h encoding.h wd-security.h
nodist_wd_security_SOURCES = VERSION.h
CLEANFILES = VERSION.h 00-wd-security.rules \
             wd-security.adoc wd-security.xml wd-security.1 \
             wd-security_*.buildinfo wd-security_*.changes \
             wd-security_*.deb wd-security_*.dsc \
             wd-security_*.tar.xz wd-security-dbgsym_*.ddeb
EXTRA_DIST = README.md INSTALL.md GEN-VERSION.sh 00-wd-security.rules.in \
             wd-security-devices.sh doc/wd-security.adoc.in debian
udevrulesdir = $(prefix)/lib/udev/rules.d
udevrules_DATA = 00-wd-security.rules
doc_DATA = README.md COPYING wd-security-devices.sh wd-security.adoc
if FOUND_ADOC
man_MANS = wd-security.1
endif
wd-security-cli.$(OBJEXT): VERSION.h
VERSION.h: FORCE
	@GIT_DIR='$(top_srcdir)/.git' GIT_WORK_TREE='$(top_srcdir)' $(SHELL) '$(top_srcdir)/GEN-VERSION.sh'
00-wd-security.rules: $(srcdir)/00-wd-security.rules.in
	sed -e 's|@bindir[@]|$(bindir)|g' $< >$@
wd-security.adoc: $(srcdir)/doc/wd-security.adoc.in
	sed -e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
	    -e 's|@PACKAGE_NAME[@]|$(PACKAGE_NAME)|g' \
	    -e 's|@PACKAGE_VERSION[@]|$(PACKAGE_VERSION)|g' \
	    -e 's|@PACKAGE_URL[@]|$(PACKAGE_URL)|g' \
	    -e 's|@udevrulesdir[@]|$(udevrulesdir)|g' \
	    -e 's|@docdir[@]|$(docdir)|g' \
	    $< >$@
wd-security.1: wd-security.adoc
	$(ADOC2MAN) $<
.PHONY: FORCE
dist-hook:
	@version=`GIT_DIR='$(top_srcdir)/.git' GIT_WORK_TREE='$(top_srcdir)' $(SHELL) '$(top_srcdir)/GEN-VERSION.sh' -n` && \
	rm -f '$(distdir)/GEN-VERSION.sh' && \
	sed -e "s/^VERSION=.*/VERSION='$$version'/" '$(top_srcdir)/GEN-VERSION.sh' >'$(distdir)/GEN-VERSION.sh'

$(distdir)/debian/%: $(srcdir)/debian/%.in | distdir
	sed -e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
	    -e 's|@PACKAGE_NAME[@]|$(PACKAGE_NAME)|g' \
	    -e 's|@PACKAGE_MAINTAINER[@]|$(PACKAGE_MAINTAINER)|g' \
	    -e 's|@PACKAGE_TARNAME[@]|$(PACKAGE_TARNAME)|g' \
	    -e 's|@PACKAGE_VERSION[@]|$(PACKAGE_VERSION)|g' \
	    -e 's|@PACKAGE_URL[@]|$(PACKAGE_URL)|g' \
	    -e "s|Thu, 01 Jan 1970 00:00:00 +0000|`date -R`|g" \
	    $< >$@
deb: distdir $(distdir)/debian/changelog $(distdir)/debian/control $(distdir)/debian/copyright
	(cd $(distdir) && dpkg-buildpackage --no-sign)
	$(am__post_remove_distdir)
