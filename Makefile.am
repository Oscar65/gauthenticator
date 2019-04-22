AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I build
CFLAGS = `pkg-config --cflags gtk+-3.0` `pkg-config --libs gtk+-3.0`

bin_PROGRAMS = gauthenticator

dist_man_MANS = man/gauthenticator.1

dist_doc_DATA = README.md

dist_pixmaps_PIXMAPS = pixmaps/gauthenticator.png

dist_desktop_DESKTOP = applications/gauthenticator.desktop

EXTRA_DIST = \
applications/gauthenticator.desktop \
pixmaps/gauthenticator.png

pixmapdir = $(datadir)/pixmaps/
pixmap_DATA = pixmaps/gauthenticator.png

Applicationsdir = $(datadir)/applications
Applications_DATA = applications/gauthenticator.desktop

CORE_SRC = src/base32.h src/base32.c
CORE_SRC += src/hmac.h src/hmac.c
CORE_SRC += src/sha1.h src/sha1.c

gauthenticator_SOURCES = \
	src/gauthenticator.c \
	$(CORE_SRC)


test: check


super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ m4 missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile
	rm -fr build/*
