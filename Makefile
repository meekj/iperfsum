CC=$(CXX)
CXXFLAGS=-std=c++11
CXXLIBS =  -L/usr/lib/x86_64-linux-gnu  -lpcap

iperfsum: iperfsum.o

clean:
	rm -rf iperfsum iperfsum.o
