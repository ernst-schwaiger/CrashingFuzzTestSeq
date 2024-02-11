#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <span>
#include <numeric> // iota
#include <iomanip>

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
typedef int (*FuzzFuncType)(const uint8_t *Data, size_t Size);
const std::string TRACK_FILE_NAME = "FuzzTestCases.bin";

class FuzzTestTracker
{
public:
    explicit FuzzTestTracker()
    {
        // truncates whatever the file contained previously
        std::fstream f(TRACK_FILE_NAME, std::ios_base::binary | std::ios_base::out);
    };

    void addFuzzTest(const uint8_t *Data, size_t Size)
    {
        std::fstream f(TRACK_FILE_NAME, std::ios_base::app | std::ios_base::binary | std::ios_base::out);
        // write length field as little endian, then actual data
        f 
            << static_cast<uint8_t>(Size & 0xff) 
            << static_cast<uint8_t>((Size >> 8) & 0xff) 
            << static_cast<uint8_t>((Size >> 16) & 0xff) 
            << static_cast<uint8_t>((Size >> 24) & 0xff);

        f.write(reinterpret_cast<char const *>(Data), Size);
    }
};

template <size_t MAX_TC_SIZE>
class FuzzTestCaseBuffer
{
public:
    explicit FuzzTestCaseBuffer(std::fstream &f, FuzzFuncType fuzzFunc) : 
        m_fuzzFunc(fuzzFunc),
        m_memBuf(getFileMemBuf(f)),
        m_testCaseOffsets(getTestCaseOffsets(m_memBuf))
    {
        m_tcBuf.fill(0);
    }

    std::vector<size_t> getMinimalTestCasesForCrash() const
    {
        std::vector<size_t> testCasesReqForCrash; // indices of test cases must be executed first for the crash
        std::vector<size_t> testCases(getNumberOfTestCases()); // index list 0..n-1 to copy from
        std::iota(begin(testCases), end(testCases), 0);

        auto itTestCasesStart = begin(testCases);

        while (itTestCasesStart < end(testCases))
        {
            // + 1 below -> round the midpoint "up"
            size_t midPoint = (distance(itTestCasesStart, end(testCases)) + 1) / 2;

            // find the longest test case sequence [itTestCasesStart, ...] that does not contribute to the crash
            while (midPoint >= 1)
            {
                auto itAppendBegin = itTestCasesStart + midPoint;
                std::vector<size_t> newTestCases = createVector(testCasesReqForCrash, itAppendBegin, end(testCases));
                if (testCasesCrash(newTestCases))
                {
                    std::cout << "Found Test suite required for crash, size: " << newTestCases.size() << "\n";
                    break;
                }
                // no crash detected, try second half of the skipped part
                midPoint = midPoint / 2;
            }

            // no test case sequence starting with itTestCasesStart was found that does not contribute to the crash
            // -> proof that *itTestCasesStart must be executed for the crash
            if (midPoint == 0)
            {
                testCasesReqForCrash.push_back(*itTestCasesStart);
                itTestCasesStart++;
            }
            else
            {   
                // move itTestCasesStart across the interval of test cases that are not needed for the crash
                itTestCasesStart = itTestCasesStart + midPoint;
            }
        }

        return testCasesReqForCrash;
    }

    size_t getNumberOfTestCases() const { return m_testCaseOffsets.size(); }

    void dumpTestCases(std::vector<size_t> tcsIdxs)
    {
        for (auto const &tcIdx : tcsIdxs)
        {
            std::stringstream stringStr;
            stringStr << "tc_" << std::setw(6) << std::setfill('0') << tcIdx << ".bin";

            std::fstream f(stringStr.str(), std::ios_base::binary | std::ios_base::out);
            if (f.good())
            {
                auto tc = getTestCaseAt(tcIdx);
                f.write(reinterpret_cast<char const *>(tc.data()), tc.size_bytes());
            }
        }
    }

private:
    
    std::span<uint8_t const> getTestCaseAt(size_t idx) const
    {
        std::span<uint8_t const> ret;

        if (idx < m_testCaseOffsets.size())
        {
            uint32_t offset = m_testCaseOffsets[idx];
            uint32_t nextOffset =
                m_testCaseOffsets.size() == (idx + 1) ? m_memBuf.size() + 4 : m_testCaseOffsets[idx + 1];
            uint32_t length = (nextOffset - 4) - offset;
            uint8_t *pDest = &m_tcBuf[MAX_TC_SIZE - length];
            // Put the test case  right-aligned into our buffer to find overflows immediately
            // FIXME: The other parts of the buffer should be poisoned
            std::copy(&m_memBuf[offset], &m_memBuf[offset + length], pDest);

            ret = std::span<uint8_t const>(pDest, static_cast<size_t>(length));
        }

        return ret;
    }
    
    std::vector<uint8_t> getFileMemBuf(std::fstream &f) const
    {
        // get the length of the file
        bool fail = f.fail();
        f.seekg(0, std::ios_base::end);
        fail |= f.fail();
        size_t fileSize = f.tellg();
        fail |= f.fail();
        f.seekg(0, std::ios_base::beg);
        fail |= f.fail();

        if (!fail)
        {
            // will contain the data
            std::vector<uint8_t> ret(fileSize);
            f.read(reinterpret_cast<char *>(ret.data()), fileSize);
            return ret;
        }
        else
        {
            return std::vector<uint8_t>();
        }
    }

    std::vector<uint32_t> getTestCaseOffsets(std::vector<uint8_t> const &m_memBuf) const
    {
        std::vector<uint32_t> ret;
        auto it = std::begin(m_memBuf);

        while ((it + 4) <= std::end(m_memBuf))
        {
            ret.push_back(std::distance(std::begin(m_memBuf), (it + 4)));
            uint32_t len = *it;
            len += (*(it + 1)) << 8;
            len += (*(it + 2)) << 16;
            len += (*(it + 3)) << 24;

            it += (len + 4);
        }

        return ret;
    }

    static std::vector<size_t> createVector(std::vector<size_t> const &startElements, std::vector<size_t>::const_iterator appendStart, std::vector<size_t>::const_iterator appendEnd)
    {
        std::vector<size_t> ret = startElements;
        ret.reserve(ret.size() + std::distance(appendStart, appendEnd));
        ret.insert(std::end(ret), appendStart, appendEnd);
        return ret;
    }

    // returns true if the passed test case sequence crashed
    bool testCasesCrash(std::vector<size_t> testCases) const
    {
        pid_t childPid = fork();
        if (childPid == 0)
        {
            fclose(stdin);
            fclose(stdout);
            fclose(stderr);
            open("/dev/null", O_RDONLY);
            open("/dev/null", O_RDWR);
            open("/dev/null", O_RDWR);

            // Child process
            for (size_t tcIdx : testCases)
            {
                auto tc = getTestCaseAt(tcIdx);
                m_fuzzFunc(tc.data(), tc.size_bytes());
            }

            // we survived, pass zero back to the parent
            exit(0);
        }
        else
        {
            // Parent process: pick up status of child
            int childStatus = 0;
            wait(&childStatus);
            return (WEXITSTATUS(childStatus) != 0);
        }
    }

    FuzzFuncType m_fuzzFunc;
    std::vector<uint8_t> m_memBuf;
    std::vector<uint32_t> m_testCaseOffsets;
    std::array<uint8_t, MAX_TC_SIZE> mutable m_tcBuf;
};

#ifdef EXTRACT_TESTS
int main()
{
    std::fstream f(TRACK_FILE_NAME, std::ios_base::binary | std::ios_base::in);
    if (f.good())
    {
        FuzzTestCaseBuffer<4096> ftb(f, LLVMFuzzerTestOneInput);
        std::cout << "Total number of test cases found: " << ftb.getNumberOfTestCases() << "\n";
        std::vector<size_t> minimalTestCaseSequence = ftb.getMinimalTestCasesForCrash();
        std::cout << "Dumping minimal test case set causing the crash to current folder...\n";
        ftb.dumpTestCases(minimalTestCaseSequence);
    }
    else
    {
        std::cout << "Could not open test case file " << TRACK_FILE_NAME << ".\n";
    }

    return 0;
}
#endif
