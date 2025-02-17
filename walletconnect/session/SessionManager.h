#pragma once
#include "../websocket/easywsclient.h"
#include <vector>
#include <string>
#include <memory>
#include <chrono>

#include "ClientSession.h"
#include "../entity/ClientMeta.h"
#include "../entity/SocketMessage.h"


namespace WalletConnect
{
	class SessionManager
	{
	private:
        WalletConnect::ClientMeta m_MetaClient;
        WalletConnect::ClientSession m_ClientSession;
        std::unique_ptr<easywsclient::WebSocket> m_ServerConnexion;
        bool m_IsConnexionApprouved = false;
        std::string m_ServerUrl;
        std::chrono::time_point<std::chrono::high_resolution_clock> m_Start;


        inline bool IsServerConnected() { return m_IsConnexionApprouved && m_ServerConnexion; }
        void sendAckMessage(const std::string& topic);
        void creationFichierQrCode();

public:
        SessionManager(){}

        inline void SetAuthCustomToken(const std::string& authCustomToken) { m_ClientSession.SetAuthCustomToken(authCustomToken); }
        void InitServerConnexion();
        void InitClientMeta(const std::string& description,const std::string& url,const  std::vector<std::string>& icons, const std::string& name);
        void SendPublicationMessage(const std::string& method, const std::string& peerMeta);
        void SendPublicationMessage(const std::string& method, const nlohmann::json& peerMeta);
        void sendSubscriptionMessage();
        void WaitMessage();
	void InitialiseClientSession();

        virtual void OnMessageReceived(const std::string& message){}
        virtual void OnConnexionApproved(){}
        virtual void OnConnexionClosed(){}
        virtual void OnCreationFichierQrCode(std::string qrCode){}
        virtual void OnCreationMaiarLink(std::string maiarLink){}

        inline WalletConnect::ClientMeta GetMetaClient() { return m_MetaClient; }

	};

}
