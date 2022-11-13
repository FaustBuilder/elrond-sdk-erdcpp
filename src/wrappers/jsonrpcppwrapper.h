#pragma once

#include "json/jsonrpcpp.hpp"
#include <ctime>

namespace wrapper
{

class RequestWrapper : public jsonrpcpp::Request
{
public:
    RequestWrapper(const Json& json = nullptr) : Request(json){}
    RequestWrapper(const jsonrpcpp::Id& id, const std::string& method, const jsonrpcpp::Parameter& params = nullptr) 
        : jsonrpcpp::Request(id, method, params){}
    RequestWrapper(const std::string& method, const jsonrpcpp::Parameter& params = nullptr) 
        : jsonrpcpp::Request(std::time(nullptr), method, params){}

    Json to_json() const override;
};

inline Json RequestWrapper::to_json() const
{
    Json json = {{"jsonrpc", "2.0"}, {"method", method_}, {"id", id_.to_json()}};

    if (params_)
    {
        std::vector<Json> test;
        test.push_back(params_.to_json());
        json["params"] = test;
    }

    return json;
}

}