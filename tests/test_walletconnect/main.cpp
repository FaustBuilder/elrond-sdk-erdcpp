#include "TestSessionManager.h"


int main(int argc, char *argv[])
{
    std::vector<std::string> icons;
    icons.push_back("https://elrondpandas.art/assets/img/favicon/favicon-32x32.png");
    
    WalletConnect::TestSessionManager sessionManager;
    sessionManager.InitClientMeta(
        "Premiere connexion a elrond avec le plugin Unreal Engine", 
        "https://elrondpandas.art/",
        icons,
        "Elrond Panda");

    // On lance la gestion de la session.
    sessionManager.InitialiseClientSession();


    return 0;
}