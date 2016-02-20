#
# Makefile for building the dispol program
#
PREFIX ?= $(DESTDIR)/usr
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
OBJECTS = readpolicy.o context_obj.o
CC = gcc

CFLAGS ?= -g -Wall  -O2 -pipe
override CFLAGS += -I$(INCLUDEDIR)

# LDLIBS=-lfl -lselinux $(LIBDIR)/libsepol.a -L$(LIBDIR)
LDLIBS=-lselinux $(LIBDIR)/libsepol.a -L$(LIBDIR)


readpolicy : $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDLIBS) -o readpolicy

context_obj.o: context_obj.c readpolicy.h
readpolicy.o: readpolicy.c readpolicy.h

.PHONY: clean
clean:
	-rm -f readpolicy *.o 
