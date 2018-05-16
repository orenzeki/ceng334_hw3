CXX=g++
CXXFLAGS=-Wall -std=c++14 -Og -ggdb

.PHONY:
all: recover

recover: main.cpp ext2.h
	$(CXX) $(CXXFLAGS) main.cpp -o recover

.PHONY:
clean:
	rm -f *.o recover
