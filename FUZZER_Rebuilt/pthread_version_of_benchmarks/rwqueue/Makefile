include ../benchmarks.mk

TESTNAME = rwqueue

all: $(TESTNAME)

$(TESTNAME): main.cc readerwriterqueue.h
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS)

clean:
	rm -f $(TESTNAME) *.o
