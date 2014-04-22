PROGRAM = acceltcp

OBJECTS = evsock.o http_handler.o http_parser.o

PRIVATE := ~/LOCAL

CFLAGS  := $(CFLAGS) -g -O2 -W -Wall -Wno-unused-parameter -Wno-deprecated-declarations -I $(PRIVATE)/include
LDFLAGS := $(LDFLAGS) -L $(PRIVATE)/lib -lev -lssl -lcrypto

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(PROGRAM)

$(PROGRAM): % : %.o $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(PROGRAM) $(PROGRAM:=.o) $(OBJECTS)
