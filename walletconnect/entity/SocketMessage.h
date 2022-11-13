#pragma once

#include "erdsdk.h"
#include <string>
#include <vector>


namespace WalletConnect
{
	struct SocketMessage {
		std::string topic;
		std::string type;
		std::string payload;
		bool silent;
	};

	static void to_json(nlohmann::json& j, const SocketMessage& p) {
		j = nlohmann::json{ {"topic", p.topic}, {"type", p.type}, {"payload", p.payload}, {"silent", p.silent} };
	}

	static void from_json(const nlohmann::json& j, SocketMessage& p) {
		j.at("topic").get_to(p.topic);
		j.at("type").get_to(p.type);
		j.at("payload").get_to(p.payload);
		j.at("silent").get_to(p.silent);
	}

	struct EncryptionPayload {
		std::string data;
		std::string hmac;
		std::string iv;
	};

	static void to_json(nlohmann::json& j, const EncryptionPayload& p) {
		j = nlohmann::json{ {"data", p.data}, {"hmac", p.hmac}, {"iv", p.iv} };
	}

	static void from_json(const nlohmann::json& j, EncryptionPayload& p) {
		j.at("data").get_to(p.data);
		j.at("hmac").get_to(p.hmac);
		j.at("iv").get_to(p.iv);
	}

}
