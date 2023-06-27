# Makefile
#
include ../Makefile.inc

SONAME=0
DEVLIB = libmpathcmd.so
LIBS = $(DEVLIB).$(SONAME)

CFLAGS += -fPIC

OBJS = mpath_cmd.o

all: $(LIBS)

$(LIBS): $(OBJS)
	$(CC) $(LDFLAGS) $(SHARED_FLAGS) -Wl,-soname=$@ $(CFLAGS) -o $@ $(OBJS) $(LIBDEPS)
	ln -sf $@ $(DEVLIB)

install: $(LIBS)
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(syslibdir)
	$(INSTALL_PROGRAM) -m 755 $(LIBS) $(DESTDIR)$(syslibdir)/$(LIBS)
	ln -sf $(LIBS) $(DESTDIR)$(syslibdir)/$(DEVLIB)
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(includedir)
	$(INSTALL_PROGRAM) -m 644 mpath_cmd.h $(DESTDIR)$(includedir)

uninstall:
	rm -f $(DESTDIR)$(syslibdir)/$(LIBS)
	rm -f $(DESTDIR)$(syslibdir)/$(DEVLIB)
	rm -f $(DESTDIR)$(includedir)/mpath_cmd.h

clean:
	rm -f core *.a *.o *.gz *.so *.so.*
