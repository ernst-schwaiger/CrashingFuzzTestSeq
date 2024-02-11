# CrashingFuzzTestSeq
If the crashfile of a Fuzzer does not crash: Finds a minimal sequence Fuzz Tests that do crash

Software modules may contain a hidden state which is -unintentionally- not reset whenever a new Fuzz Test is executed. If a Fuzz Test crashes and that crash depends on the hidden state set by one or more previously
executed Fuzz Tests, re-executing the single crashfile won't reproduce the crash.

For crash reproduction, an executing a sequence of Fuzz Tests is required. Several Fuzzer frameworks remove Fuzz Test files from the CORPUS, so the full Fuzz Test sequence may not reproducible using the CORPUS folder alone, storing the complete Fuzz Test sequence to a dedicated file is required.

The stored Fuzz Test sequence will reproduce the crash, but it likely contains thousands of tests, most of which are not required for reproducing the crash. Minimizing the sequence by removing all (for the crash) irrelevant Fuzz Tests reduces the efforts for replaying the crash and for finding the cause of the crash.

``CrashingFuzzTestSeq.h`` supports storing the complete Fuzz Test sequence in a dedicated binary file ``FuzzTestCases.bin`` while the Fuzzer is running, independent from the CORPUS. In the second step, a dedicated executable reads in the binary file to reproduce the complete Fuzz Test sequence, then replays sub sequences in order while testing if they crash or not. In the end, the second step reproduces a minimal list of binary files of the format ``tc_<idx>.bin``. They can be used to reproduce the crash, e.g. by ``find -name "tc_*.bin | sort | xargs <FuzzerBinary>``.

The files in the ``src`` folder contain an example test function with hidden state and the usage of ``CrashingFuzzTestSeq.h`` with the usage of LibFuzzer.

``Fuzzer`` is the ordinary fuzz binary, ``TrackTests`` is the same as ``Fuzzer``, but additionally produces ``FuzzTestCases.bin``. ``ExtractTests`` reads in that file and procudes the minimal set of ``tc_<idx>.bin`` test files.