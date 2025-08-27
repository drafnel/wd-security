bin_PROGRAMS = wd-security
wd_security_SOURCES = wd-security-cli.c wd-security.c encoding.c compat.c
wd_security_SOURCES += compat.h encoding.h wd-security.h
nodist_wd_security_SOURCES = VERSION.h
CLEANFILES = VERSION.h 00-wd-security.rules \
             wd-security.adoc wd-security.xml wd-security.1
EXTRA_DIST = README.md INSTALL.md GEN-VERSION.sh 00-wd-security.rules.in \
             wd-security-devices.sh doc/wd-security.adoc.in
udevrulesdir = $(libdir)/udev/rules.d
udevrules_DATA = 00-wd-security.rules
doc_DATA = README.md COPYING wd-security-devices.sh wd-security.adoc
if FOUND_A2X
man_MANS = wd-security.1
endif
wd-security.$(OBJEXT): VERSION.h
VERSION.h: FORCE
	@GIT_DIR='$(top_srcdir)/.git' GIT_WORK_TREE='$(top_srcdir)' $(SHELL) '$(top_srcdir)/GEN-VERSION.sh'
00-wd-security.rules: $(srcdir)/00-wd-security.rules.in
	sed -e 's|@bindir[@]|$(bindir)|g' $< >$@
wd-security.adoc: $(srcdir)/doc/wd-security.adoc.in
	sed -e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
	    -e 's|@PACKAGE_NAME[@]|$(PACKAGE_NAME)|g' \
	    -e 's|@PACKAGE_VERSION[@]|$(PACKAGE_VERSION)|g' \
	    -e 's|@PACKAGE_URL[@]|$(PACKAGE_URL)|g' \
	    -e 's|@libdir[@]|$(libdir)|g' \
	    -e 's|@docdir[@]|$(docdir)|g' \
	    $< >$@
wd-security.1: wd-security.adoc
	$(A2X) --doctype manpage --format manpage $<
.PHONY: FORCE
dist-hook:
	@version=`GIT_DIR='$(top_srcdir)/.git' GIT_WORK_TREE='$(top_srcdir)' $(SHELL) '$(top_srcdir)/GEN-VERSION.sh' -n` && \
	rm -f '$(distdir)/GEN-VERSION.sh' && \
	sed -e "s/^VERSION=.*/VERSION='$$version'/" '$(top_srcdir)/GEN-VERSION.sh' >'$(distdir)/GEN-VERSION.sh'
