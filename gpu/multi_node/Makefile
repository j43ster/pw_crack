NVCC= nvcc
NVCCFLAGS= -O3 -arch=sm_20
CUDA_INC=-I/usr/local/cuda/common/inc
CUDA_LIBS=-L/usr/local/cuda/lib64 -lcudart

default: all

BINS= gpu_pw_crack

all: $(BINS)

gpu_pw_crack: sha1_gpu.cu
	$(NVCC) $(NVCCFLAGS) $(CUDA_INC) $(CUDA_LIBS) $^ -o $@

clean:
	rm -rf *.o *.gch $(BINS)
