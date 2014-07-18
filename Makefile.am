# Avoiding $(libdir) because Debian does not put it under /usr/lib
methodsdir = $(prefix)/lib/apt/methods

methods_PROGRAMS = tor
tor_SOURCES = tor.cc tor.h server.cc server.h apti18n.h

install-exec-hook:
	cd $(DESTDIR)$(methodsdir) && \
	  $(LN_S) tor tor+https && \
	  $(LN_S) tor tor+http

EXTRA_DIST = README.md
