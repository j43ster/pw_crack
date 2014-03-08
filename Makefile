CC= gcc
CPP=g++
CFLAGS =
NVCC= nvcc
NVCCFLAGS= -c -O3 -arch=sm_20
CUDA_INC=-I/usr/local/cuda/common/inc
CUDA_LIBS=-L/usr/local/cuda/lib64 -lcudart

default: all

BINS= cpu_pw_crack gpu_pw_crack

all: $(BINS)

cpu_pw_crack: main.c sha1.c
	mpic++ $(CFLAGS) $^ -o $@

gpu_pw_crack: main_gpu.cpp sha1_gpu.cu
	$(NVCC) $(NVCFLAGS) $(CUDA_INC) -O -c sha1_gpu.cu
	$(CPP) -c main_gpu.cpp
	$(CPP) $(CUDA_LIBS) -O sha1_gpu.o main_gpu.o -o $@

clean:
	rm -rf *.o *.gch $(BINS)
