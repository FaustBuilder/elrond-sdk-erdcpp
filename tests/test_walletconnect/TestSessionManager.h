#pragma once
#include "session/SessionManager.h"


namespace WalletConnect
{
	class TestSessionManager : public SessionManager
	{
	private:

        public:
        TestSessionManager() : SessionManager() {}

        void OnMessageReceived(const std::string& message) override;
        void OnConnexionApproved() override;
        void OnConnexionClosed() override;
        void OnCreationFichierQrCode(std::string qrCode) override;
        void OnCreationMaiarLink(std::string maiarLink) override;
	};

}
