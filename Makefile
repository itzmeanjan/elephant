CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3 -march=native
IFLAGS = -I ./include

all: test_kat

lib:
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) -fPIC --shared wrapper/elephant.cpp -o wrapper/libelephant.so

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla && python3 -m black wrapper/python/*.py

test_kat:
	bash test_kat.sh
