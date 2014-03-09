CC= gcc
CFLAGS =

default: all

BINS= cpu_pw_crack

all: $(BINS)

cpu_pw_crack: main.c sha1.c
	mpic++ $(CFLAGS) $^ -o $@

clean:
	rm -rf *.o *.gch $(BINS)
