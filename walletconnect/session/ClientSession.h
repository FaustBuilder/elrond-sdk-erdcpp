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
		std::string m_Sign;
		std::string m_AuthCustomToken;
		std::vector<std::string> m_Accounts;
		int m_ChainID;
		ClientMeta m_DappMeta;
		

	public:
		ClientSession();


		inline std::string GetSign() const { return m_Sign; }
		inline std::string GetBridgeURL() const { return m_BridgeURL; }
		inline std::string GetTopic() const { return m_Topic; }
		inline std::string GetPeerID() const { return m_PeerID; }
		inline std::vector<uint8_t> GetKeyArray() const { return m_KeyArray; }
		inline std::string GetQrCodeUrl() const { return m_QrCodeUrl; }
		inline std::vector<std::string> GetAccounts() const { return m_Accounts; }
		inline int GetChainID() const { return m_ChainID; }
		inline std::string GetMaiarWalletLink() const {return m_MaiarWalletLink; }
		
		inline void AddAccount(const std::string& account) { m_Accounts.push_back(account); }
		inline void SetChainID(int chainID) { m_ChainID = chainID; }
		void SetDappMeta(const std::string& description, const std::string& url, const std::vector<std::string>& icons, const std::string& name);
		inline void SetSign(const std::string& sign) { m_Sign = sign; }
		inline void SetAuthCustomToken(const std::string& authCustomToken) { m_AuthCustomToken = authCustomToken; }


	private:
		void calculateBridgeURL();
		void calculateKey();
		std::string genererGUID();
		std::string string_to_hex(const std::string& input);
		std::string urlencode(std::string s);
		void hexchar(unsigned char c, unsigned char& hex1, unsigned char& hex2);
	};

};
