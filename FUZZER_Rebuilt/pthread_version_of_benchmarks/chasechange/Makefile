include ../benchmarks.mk

TESTNAME = chasechange

HEADERS = deque.h
OBJECTS = main.o deque.o

all: $(TESTNAME)

$(TESTNAME): $(HEADERS) $(OBJECTS)
	$(CXX) -o $@ $(OBJECTS) $(CXXFLAGS) $(LDFLAGS) -w

%.o: %.c
	$(CXX) -c -o $@ $< $(CXXFLAGS) -w

clean:
	rm -f $(TESTNAME) *.o
