# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@opensvc.com>
#
include ../Makefile.inc

OBJS = main.o

CFLAGS += -fPIE -DPIE -I$(multipathdir) -I$(mpathcmddir)
LDFLAGS += -lpthread -ldevmapper -ldl -L$(multipathdir) -lmultipath -ludev \
	-L$(mpathcmddir) -lmpathcmd -pie

EXEC = multipath

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(EXEC) $(LDFLAGS)
	$(GZIP) $(EXEC).8 > $(EXEC).8.gz
	$(GZIP) $(EXEC).conf.5 > $(EXEC).conf.5.gz
	$(GZIP) mpathconf.8 > mpathconf.8.gz

install:
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) -m 755 $(EXEC) $(DESTDIR)$(bindir)/
	$(INSTALL_PROGRAM) -m 755 mpathconf $(DESTDIR)$(bindir)/
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(libudevdir)/rules.d
	$(INSTALL_PROGRAM) -m 644 multipath.rules $(DESTDIR)$(libudevdir)/rules.d/62-multipath.rules
	$(INSTALL_PROGRAM) -m 644 11-dm-mpath.rules $(DESTDIR)$(libudevdir)/rules.d/11-dm-mpath.rules
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(mandir)
	$(INSTALL_PROGRAM) -m 644 $(EXEC).8.gz $(DESTDIR)$(mandir)
	$(INSTALL_PROGRAM) -d $(DESTDIR)$(man5dir)
	$(INSTALL_PROGRAM) -m 644 $(EXEC).conf.5.gz $(DESTDIR)$(man5dir)
	$(INSTALL_PROGRAM) -m 644 mpathconf.8.gz $(DESTDIR)$(mandir)

uninstall:
	rm $(DESTDIR)$(libudevdir)/rules.d/62-multipath.rules
	rm $(DESTDIR)$(libudevdir)/rules.d/11-dm-mpath.rules
	rm $(DESTDIR)$(bindir)/$(EXEC)
	rm $(DESTDIR)$(bindir)/mpathconf
	rm $(DESTDIR)$(mandir)/$(EXEC).8.gz
	rm $(DESTDIR)$(man5dir)/$(EXEC).conf.5.gz
	rm $(DESTDIR)$(mandir)/mpathconf.8.gz

clean:
	rm -f core *.o $(EXEC) *.gz
