# Makefile.inc
#
# Copyright (C) 2004 Christophe Varoqui, <christophe.varoqui@opensvc.com>

#
# Allow to force some libraries to be used statically. (Uncomment one of the
# following lines or define the values when calling make.)
#
# WITH_LOCAL_LIBDM	= 1
# WITH_LOCAL_LIBSYSFS	= 1

ifeq ($(TOPDIR),)
	TOPDIR	= ..
endif

ifndef LIB
	ifeq ($(shell test -d /lib64 && echo 1),1)
		LIB=lib64
	else
		LIB=lib
	endif
endif

prefix      = 
exec_prefix = $(prefix)
bindir      = $(exec_prefix)/usr/sbin
libudevdir  = ${prefix}/usr/lib/udev
multipathdir = $(TOPDIR)/libmultipath
mandir      = $(prefix)/usr/share/man/man8
man5dir     = $(prefix)/usr/share/man/man5
man3dir      = $(prefix)/usr/share/man/man3
rcdir	    = $(prefix)/etc/rc.d/init.d
syslibdir   = $(prefix)/usr/$(LIB)
libdir	    = $(prefix)/usr/$(LIB)/multipath
unitdir     = $(prefix)/lib/systemd/system
mpathpersistdir = $(TOPDIR)/libmpathpersist
includedir  = $(prefix)/usr/include
mpathcmddir = $(TOPDIR)/libmpathcmd
libdmmpdir     = $(TOPDIR)/libdmmp
nvmedir     = $(TOPDIR)/libmultipath/nvme
pkgconfdir     = $(prefix)/usr/$(LIB)/pkgconfig

GZIP            = /bin/gzip -9 -c
RM              = rm -f
LN              = ln -sf
INSTALL_PROGRAM = install

ifndef RPM_OPT_FLAGS
	RPM_OPT_FLAGS = -O2 -g -pipe -Wformat-security -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4
endif

LDFLAGS     += -Wl,-z,relro -Wl,-z,now
OPTFLAGS     = $(RPM_OPT_FLAGS) -Wunused -Wstrict-prototypes
CFLAGS	     = $(OPTFLAGS) -DLIB_STRING=\"${LIB}\"
SHARED_FLAGS = -shared

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

