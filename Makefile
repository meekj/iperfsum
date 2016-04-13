CC=$(CXX)
#CC = clang++-3.6
CXXFLAGS = -std=c++11
LFLAGS = -L/usr/lib/x86_64-linux-gnu
LIBS = -lpcap

iperfsum: iperfsum.o
	$(CC) $(CXXFLAGS) -o iperfsum iperfsum.cpp $(LIBS)

clean:
	rm -rf iperfsum iperfsum.o
