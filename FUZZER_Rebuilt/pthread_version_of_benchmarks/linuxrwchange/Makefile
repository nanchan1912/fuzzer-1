include ../benchmarks.mk

TESTNAME = linuxrwchange

all: $(TESTNAME)

$(TESTNAME): $(TESTNAME).cc
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS) -w

clean:
	rm -f $(TESTNAME) *.o
