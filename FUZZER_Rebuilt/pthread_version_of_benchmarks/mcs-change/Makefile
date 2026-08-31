include ../benchmarks.mk

TESTNAME = mcs-change

all: $(TESTNAME)

$(TESTNAME): $(TESTNAME).cc $(TESTNAME).h
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS) -w

clean:
	rm -f $(TESTNAME) *.o
