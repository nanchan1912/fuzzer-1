To build and run the analysis for all benchmarks, run:

```bash
cd pthread_version_of_benchmarks
./run_benchmarks.sh build   # build the analysis (takes ~1-2 minutes)
./run_benchmarks.sh         # to just run the analysis on all benchmarks without building
```

File Structure
----------------

```wmm-ccfg-generation
├── pthread_version_of_benchmarks/
│   └── dekker-change/
│       ├── generated_output.pg    # generated CCFG for dekker-change
│       └── data/
│           └── no_pass.ll         # LLVM IR used as input to SVF for CCFG generation
└── src/
	└── anal.cpp                   # analysis implementation (anal.cpp)
```