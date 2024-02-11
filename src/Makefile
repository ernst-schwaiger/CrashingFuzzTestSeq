CPP=clang++
CCOPTS=-O0 -ggdb3 -Wall -std=c++20


all: Fuzzer ExtractTests TrackTests



Fuzzer: Fuzzer.o TestFunction.o
	$(CPP) $(CCOPTS) -fsanitize=address,fuzzer Fuzzer.o TestFunction.o -o Fuzzer

TrackTests: TrackTests.o TestFunction.o
	$(CPP) $(CCOPTS) -fsanitize=address,fuzzer TrackTests.o TestFunction.o -o TrackTests

ExtractTests: ExtractTests.o TestFunction.o
	$(CPP) $(CCOPTS) -fsanitize=address ExtractTests.o TestFunction.o -o ExtractTests

TestFunction.o: TestFunction.cpp
	$(CPP) -c $(CCOPTS) -fsanitize=address,fuzzer TestFunction.cpp -o TestFunction.o

Fuzzer.o: Fuzzer.cpp
	$(CPP) -c $(CCOPTS) -fsanitize=address,fuzzer Fuzzer.cpp -o Fuzzer.o

TrackTests.o: Fuzzer.cpp
	$(CPP) -c $(CCOPTS) -fsanitize=address -DTRACK_TESTS Fuzzer.cpp -o TrackTests.o

ExtractTests.o: Fuzzer.cpp
	$(CPP) -c $(CCOPTS) -fsanitize=address -DEXTRACT_TESTS Fuzzer.cpp -o ExtractTests.o

clean:
	rm -rf Fuzzer ExtractTests TrackTests *.o


clobber: clean
	rm -rf *.bin crash-*