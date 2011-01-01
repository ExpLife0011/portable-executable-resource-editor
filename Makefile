all: usage

usage: usage.cpp PERE.cpp PERE.h
	@g++ -Wall -std=c++11 -Wno-write-strings usage.cpp PERE.cpp -o usage

clean:
	@rm -f usage
