CC= gcc
CPP=g++
CFLAGS =
NVCC= nvcc
NVCCFLAGS= -O3 -arch=sm_20
CUDA_INC=-I/usr/local/cuda/common/inc
CUDA_LIBS=-L/usr/local/cuda/lib64 -lcudart

default: all

BINS= cpu_pw_crack gpu_pw_crack

all: $(BINS)

cpu_pw_crack: main.c sha1.c
	mpic++ $(CFLAGS) $^ -o $@

gpu_pw_crack: sha1_gpu.cu
	$(NVCC) $(NVCCFLAGS) $(CUDA_INC) $(CUDA_LIBS) $^ -o $@

clean:
	rm -rf *.o *.gch $(BINS)
