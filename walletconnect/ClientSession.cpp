#include "ClientSession.h"

#include <random>
#include <chrono>
#ifdef _WIN32
#include <Objbase.h> //GUID
#else
#include <uuid/uuid.h>
#endif

namespace WalletConnect
{

    void ClientSession::hexchar(unsigned char c, unsigned char& hex1, unsigned char& hex2)
    {
        hex1 = c / 16;
        hex2 = c % 16;
        hex1 += hex1 <= 9 ? '0' : 'a' - 10;
        hex2 += hex2 <= 9 ? '0' : 'a' - 10;
    }

    std::string ClientSession::urlencode(std::string s)
    {
        const char* str = s.c_str();
        std::vector<char> v(s.size());
        v.clear();
        for (size_t i = 0, l = s.size(); i < l; i++)
        {
            char c = str[i];
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
                c == '*' || c == '\'' || c == '(' || c == ')')
            {
                v.push_back(c);
            }
            else if (c == ' ')
            {
                v.push_back('+');
            }
            else
            {
                v.push_back('%');
                unsigned char d1, d2;
                hexchar(c, d1, d2);
                v.push_back(d1);
                v.push_back(d2);
            }
        }

        return std::string(v.cbegin(), v.cend());
    }

	ClientSession::ClientSession()
	{
        calculateBridgeURL();
        Topic = genererGUID();
        PeerID = genererGUID();
        calculateKey();
        VersionEncode = "1";
        std::string BridgeUrlEncode(urlencode(BridgeURL));
        QrCodeUrl = "wc:" + Topic + "@" + VersionEncode + "?bridge=" + BridgeUrlEncode + "&key=" + Key;
	}

    void ClientSession::SetDappMeta(std::string description, std::string url, std::vector<std::string> icons, std::string name)
	{
        DappMeta.description = description;
        DappMeta.url = url;
        DappMeta.icons = icons;
        DappMeta.name = name;
	}

	void ClientSession::calculateBridgeURL()
	{
        // calcul url bridge
        const std::string AlphaNumeric = "abcdefghijklmnopqrstuvwxyz0123456789";

        // calcul de chiffre alÈatoire
        std::default_random_engine re(std::chrono::system_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<int> distrib{ 0, 39 };

        BridgeURL = "https://";
        BridgeURL.push_back(AlphaNumeric[distrib(re)]);
        BridgeURL.append(".bridge.walletconnect.org");
	}

    std::string ClientSession::string_to_hex(const std::string& input)
    {
        static const char hex_digits[] = "0123456789ABCDEF";

        std::string output;
        output.reserve(input.length() * 2);
        for (unsigned char c : input)
        {
            output.push_back(std::tolower(hex_digits[c >> 4]));
            output.push_back(std::tolower(hex_digits[c & 15]));
        }
        return output;
    }

    void ClientSession::calculateKey()
    {
        // calcul de chiffre alÈatoire
        std::default_random_engine re(std::chrono::system_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<int> distrib{ 0, 255 };

        // Prep keys, not part of performance test
        KeyArray.resize(32);
        for (short i = 0; i < 32; i++)
        {
            short randomNumber = distrib(re);
            KeyArray[i] = (randomNumber);
        }
        std::string keyString(KeyArray.begin(), KeyArray.end());
        Key = string_to_hex(keyString);

        std::transform(Key.begin(), Key.end(), Key.begin(),
            [](unsigned char c) { return std::tolower(c); });

    }


    std::string ClientSession::genererGUID()
    {
        std::string guid;

#ifdef _WIN32
        GUID gidReference;
        HRESULT hCreateGuid = CoCreateGuid(&gidReference);

        // If you want to convert uuid to string, use UuidToString() function
        // Rpcrt4.lib
        RPC_CSTR szUuid = NULL;
        if (::UuidToStringA(&gidReference, &szUuid) == RPC_S_OK)
        {
            guid = (char*)szUuid;
            ::RpcStringFreeA(&szUuid);
        }
#else
    uuid_t uuid;
    uuid_generate_random ( uuid );
    char s[37];
    uuid_unparse ( uuid, s );
    guid = std::string(s);
#endif
        return guid;
    }

}
