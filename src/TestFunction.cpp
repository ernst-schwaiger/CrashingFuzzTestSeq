#include "TestFunction.h"

// This is our "hidden" state that causes crashfiles *not* to produce the problem
static uint8_t globalState = 0;

bool funcToFuzz(uint8_t const *pBuf, size_t len)
{
    bool ret = false;
    if (len == 3)
    {
        if (pBuf[0] == 'd')
        {
            if (pBuf[1] == 'e')
            {
                ++globalState;                
                if (pBuf[2] == globalState) // and here we are using this state
                {
                    if (pBuf[3] == 'p')
                    {
                        ret = true;         
                    }
                }               
            }
        }
    }

    return ret;
}