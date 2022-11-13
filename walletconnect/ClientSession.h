#pragma once

#include <string>
#include <vector>
#include "entity/ClientMeta.h"

namespace WalletConnect
{
	class ClientSession
	{
	private:
		std::string BridgeURL;
		std::string Topic;
		std::string PeerID;
		std::vector<uint8_t> KeyArray;
		std::string Key;
		std::string VersionEncode;
		std::string QrCodeUrl;
		std::vector<std::string> Accounts;
		int ChainID;
		ClientMeta DappMeta;
		

		std::string ClientID;
		long HandshakeID;
		int NetworkID;
		ClientMeta WalletMetadata;
	public:
		ClientSession();


		inline std::string GetBridgeURL() { return BridgeURL; }
		inline std::string GetTopic() { return Topic; }
		inline std::string GetPeerID() { return PeerID; }
		inline std::vector<uint8_t> GetKeyArray() { return KeyArray; }
		inline std::string GetQrCodeUrl() { return QrCodeUrl; }
		inline std::vector<std::string> GetAccounts() { return Accounts; }
		inline int GetChainID() { return ChainID; }
		
		inline void AddAccount(std::string account) { Accounts.push_back(account); }
		inline void SetChainID(int chainID) { ChainID = chainID; }
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
