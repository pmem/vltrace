#
# Copyright 2014-2016, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

#
# man/Makefile -- Makefile for man page
#

#include ../src/common.inc

MANPAGES_1_MD = strace.ebpf.1.md

MANPAGES_BUILDDIR = generated

MANPAGES_1_GROFF = $(MANPAGES_1_MD:.1.md=.1)

MANPAGES_1 = $(MANPAGES_1_GROFF)


MANPAGES_GROFF_1 = $(MANPAGES_1:.1.md=.1)

MANPAGES = $(MANPAGES_GROFF_1)

MANPAGES_BUILD = $(addprefix $(MANPAGES_BUILDDIR)/, $(MANPAGES))

HTMLFILES = $(MANPAGES_BUILD:=.html)
TXTFILES = $(MANPAGES_BUILD:=.txt)

GZFILES_1 = $(MANPAGES_1:=.gz)
GZFILES = $(GZFILES_1) 

GZFILES_BUILD = $(addprefix $(MANPAGES_BUILDDIR)/, $(GZFILES))
GZFILES_1_BUILD = $(addprefix $(MANPAGES_BUILDDIR)/, $(GZFILES_1))

MANPAGES_DESTDIR_1 = $(DESTDIR)$(man1dir)

DOCS_DESTDIR = $(DESTDIR)$(docdir)

all: $(MANPAGES_BUILD) $(TXTFILES) | $(MANPAGES_BUILDDIR)

$(MANPAGES_BUILDDIR):
	$(MKDIR) -p $@

%.txt: %
	man ./$< > $@

groff: $(MANPAGES_1)

doxygen_docs:
	doxygen cppobj.Doxyfile

html: $(HTMLFILES) doxygen_docs

%.html: %
	groff -mandoc -Thtml ./$< > $@

$(MANPAGES_BUILDDIR)/%.1: %.1.md default.man ../utils/md2man.sh FORCE
	../utils/md2man.sh ./$< default.man $@

compress: $(GZFILES_BUILD)

%.gz:
	gzip -c ./$* > $@

clean:

clobber: clean
	$(RM) -rf $(DOXYGEN_HTMLDIR) \
		$(MANPAGES_BUILDDIR)/*.txt \
		$(MANPAGES_BUILDDIR)/*.html \
		$(MANPAGES_BUILDDIR)/*.gz


install: compress
	install -d $(MANPAGES_DESTDIR_1)
	install -p -m 0644 $(GZFILES_1_BUILD) $(MANPAGES_DESTDIR_1)

uninstall:
	$(foreach f, $(GZFILES_1), $(RM) $(MANPAGES_DESTDIR_1)/$(f))

FORCE:

.PHONY: all html clean compress clobber cstyle install uninstall install-cpp\
	uninstall-cpp doxygen_docs
