#pragma once

#include "erdsdk.h"
#include <string>
#include <vector>


namespace WalletConnect
{
	struct ClientMeta {
		std::string description;
		std::string url;
		std::vector<std::string> icons;
		std::string name;
	};

	static void to_json(nlohmann::json& j, const ClientMeta& p) {
		j = nlohmann::json{ {"description", p.description}, {"url", p.url}, {"icons", p.icons}, {"name", p.name} };
	}

	static void from_json(const nlohmann::json& j, ClientMeta& p) {
		j.at("description").get_to(p.description);
		j.at("url").get_to(p.url);
		j.at("icons").get_to(p.icons);
		j.at("name").get_to(p.name);
	}
}