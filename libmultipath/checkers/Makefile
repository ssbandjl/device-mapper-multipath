# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@opensvc.com>
#
include ../../Makefile.inc

LIBS= \
	libcheckcciss_tur.so \
	libcheckreadsector0.so \
	libchecktur.so \
	libcheckhp_tur.so \
	libcheckdirectio.so \
	libcheckemc_clariion.so \
	libcheckhp_sw.so \
	libcheckrdac.so

CFLAGS += -fPIC -I..

all: $(LIBS)

libcheckdirectio.so: libsg.o directio.o
	$(CC) $(LDFLAGS) $(SHARED_FLAGS) -o $@ $^ -laio

libcheck%.so: libsg.o %.o
	$(CC) $(LDFLAGS) $(SHARED_FLAGS) -o $@ $^

hp_tur.o: tur.c
	$(CC) $(CFLAGS) -DCHECK_WWID -c -o $@ $<

install:
	$(INSTALL_PROGRAM) -m 755 $(LIBS) $(DESTDIR)$(libdir)

uninstall:
	for file in $(LIBS); do rm -f $(DESTDIR)$(libdir)/$$file; done

clean:
	rm -f core *.a *.o *.gz *.so
