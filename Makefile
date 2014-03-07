CC= gcc
CPP=g++
CFLAGS =
NVCC= nvcc
NVCCFLAGS= -c -O3 -arch=sm_20

default: all

BINS= cpu_pw_crack gpu_pw_crack

all: $(BINS)

cpu_pw_crack: main.c sha1.c
	$(CC) $(CFLAGS) $^ -o $@

gpu_pw_crack: main.cu sha1.cu
	$(NVCC) $(NVCFLAGS) $^ -o $@

clean:
	rm -rf *.o *.gch $(BINS)
