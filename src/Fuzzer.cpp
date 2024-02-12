#include <iostream>
#include <fstream>

#include "TestFunction.h"
#include "CrashingFuzzTestSeq.h"

using namespace std;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, uint32_t Size)
{
#ifdef TRACK_TESTS
    static FuzzTestTracker ftt;
    ftt.addFuzzTest(Data, Size);
#endif

    funcToFuzz(Data, Size);
    return 0;  // Values other than 0 and -1 are reserved for future use.
}
