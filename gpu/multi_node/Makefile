CC=mpic++
LIBS=-lmpi
NVCC= nvcc
NVCCFLAGS= -O3 -arch=sm_20
CUDA_INC=-I/usr/local/cuda/common/inc
CUDA_LIBS=-L/usr/local/cuda/lib64 -lcudart

default: all

BINS= gpu_pw_crack

all: $(BINS)

gpu_pw_crack: main.cpp sha1_gpu.cu
	$(NVCC) $(NVCCFLAGS) $(CUDA_INC) $(CUDA_LIBS) -O -c sha1_gpu.cu
	$(CC) -c main.cpp
	$(CC) $(CUDA_LIBS) -O sha1_gpu.o main.o -o $@


clean:
	rm -rf *.o *.gch $(BINS)
