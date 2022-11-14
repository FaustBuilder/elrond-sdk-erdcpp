#include "TestSessionManager.h"
#include "utils/utils.h"
#include <fstream>

namespace WalletConnect
{
void TestSessionManager::OnMessageReceived(const std::string& message) 
{

}

void TestSessionManager::OnConnexionApproved() 
{

}

void TestSessionManager::OnConnexionClosed() 
{

}

void TestSessionManager::OnCreationFichierQrCode(std::string qrCode)
{
        qrcodegen::QrCode qr0 = qrcodegen::QrCode::encodeText(qrCode.c_str(), qrcodegen::QrCode::Ecc::LOW);
        std::string svg = toSvgString(qr0, 4);  // See QrCodeGeneratorDemo
        
        // POUR LES TESTS
        std::ofstream myfile;
        myfile.open ("test.svg");
        myfile << svg;
        myfile.close();
}

void TestSessionManager::OnCreationMaiarLink(std::string maiarLink) 
{
}


}
