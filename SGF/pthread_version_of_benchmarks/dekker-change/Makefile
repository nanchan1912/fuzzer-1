include ../benchmarks.mk

TESTNAME = dekker-change

all: $(TESTNAME)

$(TESTNAME): $(TESTNAME).cc
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS) -w

clean:
	rm -f $(TESTNAME) *.o
