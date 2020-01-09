#
# Copyright (C) 2016 FUJITSU LIMITED
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

VERSION=1.0.3
NAME=ptdump
ARCH=UNSUPPORTED

ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
  ARCH=SUPPORTED
endif

ifeq ($(shell /bin/ls /usr/include/crash/defs.h 2>/dev/null), /usr/include/crash/defs.h)
  INCDIR=/usr/include/crash
endif
ifeq ($(shell /bin/ls ./defs.h 2> /dev/null), ./defs.h)
  INCDIR=.
endif
ifeq ($(shell /bin/ls ../defs.h 2> /dev/null), ../defs.h)
  INCDIR=..
endif

SUBDIR=ptdump
TARGET_CFILES=$(SUBDIR)/fastdecode.c $(SUBDIR)/map.c ptdump.c

COMMON_CFLAGS=-Wall -I$(INCDIR) -fPIC -D$(TARGET)

all: ptdump.so

ptdump.so: $(TARGET_CFILES) $(INCDIR)/defs.h $(SUBDIR)/map.h
ifeq ($(ARCH),UNSUPPORTED)
	@echo "ptdump: architecture not supported"
else
	gcc $(CFLAGS) $(TARGET_CFLAGS) $(COMMON_CFLAGS) -nostartfiles -shared -rdynamic -o $@ $(TARGET_CFILES)
endif

debug: COMMON_CFLAGS+=-DDEBUG
debug: all

create-archive:
	@git archive --format=tar --prefix=$(NAME)-$(VERSION)/ HEAD | \
	gzip > ./$(NAME)-$(VERSION).tar.gz

tag:
	@git tag $(VERSION)
	@echo tag:$(VERSION)

clean:
	rm -f *.so *.o $(SUBDIR)/*.so $(SUBDIR)/*.o

