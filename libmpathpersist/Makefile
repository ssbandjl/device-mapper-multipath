# Makefile
#
BUILD = glibc
include ../Makefile.inc

INSTALL_PROGRAM = install

SONAME=0
DEVLIB = libmpathpersist.so
LIBS = $(DEVLIB).$(SONAME)


CFLAGS += -fPIC -I$(multipathdir) -I$(mpathpersistdir) -I$(mpathcmddir)
LIBDEPS +=  -lpthread -ldevmapper -ldl -L$(multipathdir) -lmultipath \
	-L$(mpathcmddir) -lmpathcmd

OBJS = mpath_persist.o mpath_updatepr.o mpath_pr_ioctl.o 

all: $(LIBS)


$(LIBS): 
	$(CC) -Wall -c $(CFLAGS) *.c
	$(CC) $(LDFLAGS) -shared $(LIBDEPS) -Wl,-soname=$@ $(CFLAGS) -o $@ $(OBJS)
	ln -s $(LIBS) $(DEVLIB)
	$(GZIP) mpath_persistent_reserve_in.3 > mpath_persistent_reserve_in.3.gz	
	$(GZIP) mpath_persistent_reserve_out.3 > mpath_persistent_reserve_out.3.gz	

install: $(LIBS)
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(syslibdir)
	$(INSTALL_PROGRAM) -m 755 $(LIBS) $(DESTDIR)$(syslibdir)/$(LIBS)
	$(INSTALL_PROGRAM) -m 755 -d $(DESTDIR)$(man3dir)
	ln -sf $(LIBS) $(DESTDIR)$(syslibdir)/$(DEVLIB)
	install -m 644 mpath_persistent_reserve_in.3.gz $(DESTDIR)$(man3dir)	
	install -m 644 mpath_persistent_reserve_out.3.gz $(DESTDIR)$(man3dir)	
	$(INSTALL_PROGRAM) -m 644 mpath_persist.h $(DESTDIR)$(includedir)

uninstall:
	rm -f $(DESTDIR)$(syslibdir)/$(LIBS)
	rm -f $(DESTDIR)$(syslibdir)/$(DEVLIB)
	rm $(DESTDIR)$(man3dir)/mpath_persistent_reserve_in.3.gz
	rm $(DESTDIR)$(man3dir)/mpath_persistent_reserve_out.3.gz
	rm -f $(DESTDIR)$(includedir)/mpath_persist.h

clean:
	rm -f core *.a *.o 
	rm -f libmpathpersist.so.0
	rm -f libmpathpersist.so
	rm -f mpath_persistent_reserve_in.3.gz mpath_persistent_reserve_out.3.gz
