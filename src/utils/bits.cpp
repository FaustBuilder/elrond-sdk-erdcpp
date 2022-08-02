#include "bits.h"
#include "errors.h"
#include "stdexcept"

namespace util
{
bytes convertBits(bytes const &data, unsigned int const fromBits, unsigned int const toBits, bool const pad)
{
    unsigned int acc = 0;
    unsigned int bits = 0;
    std::vector<uint8_t> ret;
    unsigned int maxVal = (1 << toBits) - 1;
    unsigned int maxAcc = (1 << (fromBits + toBits - 1)) - 1;

    for (auto const &value : data)
    {
        int valueAsInt = value & 0xff;

        if ((valueAsInt < 0) || (valueAsInt >> fromBits != 0))
        {
            throw std::invalid_argument(ERROR_MSG_CONVERT_BITS);
        }

        acc = ((acc << fromBits) | valueAsInt) & maxAcc;
        bits += fromBits;

        while (bits >= toBits)
        {
            bits -= toBits;
            ret.push_back((acc >> bits) & maxVal);
        }
    }

    if (pad)
    {
        if (bits > 0)
        {
            ret.push_back((acc << (toBits - bits)) & maxVal);
        }
    }
    else if (bits >= fromBits || ((acc << (toBits - bits)) & maxVal) != 0)
    {
        throw std::invalid_argument(ERROR_MSG_CONVERT_BITS);
    }

    return ret;
}
}
