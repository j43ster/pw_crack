default: all

all: pw_crack

pw_crack:
	gcc main.c sha1.c

clean:
	rm -rf a.out
