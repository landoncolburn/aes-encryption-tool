PROGS = a3-program
HDRS = sbox.h
SRCS = main.c

CC = gcc
CFLAGS = -Wall --std=c99

all: $(PROGS)

a3-program: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

test: $(PROGS)
	./a3-program test/test1plaintext.txt test/test1key.txt

clean:
	rm -f $(PROGS) *.o