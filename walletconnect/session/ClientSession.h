#pragma once

#include <string>
#include <vector>
#include "../entity/ClientMeta.h"

namespace WalletConnect
{
	class ClientSession
	{
	private:
		std::string m_BridgeURL;
		std::string m_Topic;
		std::string m_PeerID;
		std::vector<uint8_t> m_KeyArray;
		std::string m_Key;
		std::string m_VersionEncode;
		std::string m_QrCodeUrl;
		std::string m_MaiarWalletLink;
		std::vector<std::string> m_Accounts;
		int m_ChainID;
		ClientMeta m_DappMeta;
		

	public:
		ClientSession();


		inline std::string GetBridgeURL() { return m_BridgeURL; }
		inline std::string GetTopic() { return m_Topic; }
		inline std::string GetPeerID() { return m_PeerID; }
		inline std::vector<uint8_t> GetKeyArray() { return m_KeyArray; }
		inline std::string GetQrCodeUrl() { return m_QrCodeUrl; }
		inline std::vector<std::string> GetAccounts() { return m_Accounts; }
		inline int GetChainID() { return m_ChainID; }
		inline std::string GetMaiarWalletLink() {return m_MaiarWalletLink; }
		
		inline void AddAccount(std::string account) { m_Accounts.push_back(account); }
		inline void SetChainID(int chainID) { m_ChainID = chainID; }
		void SetDappMeta(std::string description, std::string url, std::vector<std::string> icons, std::string name);


	private:
		void calculateBridgeURL();
		void calculateKey();
		std::string genererGUID();
		std::string string_to_hex(const std::string& input);
		std::string urlencode(std::string s);
		void hexchar(unsigned char c, unsigned char& hex1, unsigned char& hex2);
	};

};
