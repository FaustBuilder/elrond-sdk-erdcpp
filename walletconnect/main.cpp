#include "erdsdk.h"
#include "websocket/easywsclient.h"
#include "session/ClientSession.h"
#include "entity/SocketMessage.h"
#include "qrcode/qrcodegen.h"
#include "wrappers/cryptosignwrapper.h"
#include "wrappers/jsonrpcppwrapper.h"
#include "session/SessionManager.h"
#include <sstream>
#include <random>
#include <chrono>
#include <iostream>
#include <fstream>


int main(int argc, char *argv[])
{
    std::vector<std::string> icons;
    icons.push_back("https://elrondpandas.art/assets/img/favicon/favicon-32x32.png");
    
    WalletConnect::SessionManager sessionManager;
    sessionManager.InitClientMeta(
        "Premiere connexion a elrond avec le plugin Unreal Engine", 
        "https://elrondpandas.art/",
        icons,
        "Elrond Panda");

    // On lance la gestion de la session.
    sessionManager.InitialiseClientSession();


    return 0;
}