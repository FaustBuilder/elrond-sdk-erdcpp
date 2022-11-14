#include "SessionManager.h"
#include "wrappers/cryptosignwrapper.h"
#include "wrappers/jsonrpcppwrapper.h"
#include "../utils/utils.h"
#include <random>
#include <chrono>
#include <fstream>

#define CBC 1
#define AES256 1

namespace WalletConnect
{

	void SessionManager::InitialiseClientSession()
    {
        m_ClientSession = WalletConnect::ClientSession();
        creationFichierQrCode();
        InitServerConnexion();
        sendSubscriptionMessage();
        nlohmann::json jMetaClient = GetMetaClient();
        SendPublicationMessage("wc_sessionRequest", jMetaClient);
        WaitMessage();
    }

    void SessionManager::InitServerConnexion()
    {
        std::string websocketURL = m_ClientSession.GetBridgeURL();
        websocketURL.replace(websocketURL.find("https"), sizeof("https") - 1, "wss");

        m_ServerConnexion = std::unique_ptr<easywsclient::WebSocket>(easywsclient::WebSocket::from_url(websocketURL));
        // m_ServerConnexion = std::make_unique<easywsclient::WebSocket>(easywsclient::WebSocket::from_url(websocketURL));
        assert(m_ServerConnexion);
        m_Start = std::chrono::high_resolution_clock::now();
    }

    void SessionManager::InitClientMeta(const std::string& description,const std::string& url,const  std::vector<std::string>& icons, const std::string& name)
    {
        m_MetaClient.description = description;
        m_MetaClient.url = url;
        m_MetaClient.icons = icons;
        m_MetaClient.name = name;
    }

    void SessionManager::sendSubscriptionMessage()
    {
        
        // Subscription
        WalletConnect::SocketMessage subscriptionMessage{ m_ClientSession.GetPeerID(), "sub", "", true };

        //const std::string subscriptionMessage = "{\"topic\":\"" + peerId + "\",\"type\":\"sub\",\"payload\":\"\", \"silent\":true}";
        //{"topic":"2cb089c5-736f-444b-9818-b9bdedfab43e","type":"sub","payload":"", "silent":true}
        m_ServerConnexion->send(nlohmann::json(subscriptionMessage).dump());
        //{"payload":"{\"data\":\"2a2041da9bfdf594f2b6643ea3a129256e3d1e9d612c09e571e3a23603d108669a944893d848a7736f66d66acf6c1eb1a39c3579b44259523ccab38f58932f8f4e298c60073fbbe45dbbef222020dfc534046be38abd85a76eab9629abbb9d85ba239d5e7ebec2a1108c4ad63e007f19683a96d4c92ef54eb357b806dfc20ef5f047215837d34792cdf3a376f921cc9a4e0bc35fca3935e624a136a05cd9aa7593d8b4ad89d0fe3dd9b58a7ef10f3e1da2238908431caa80cb8e6cf577e8b67f2153a3b204bdad672a923a1a465ce873216e67c9075328ec25eda7bcd9ed9f8ba7824fd50f4c8f335325af74a4a8fda13b1a707038a227e54391c9612a7b81e4be303d84bb6f358477f5634cb9b16b725b253502d2ad36b4b3a97e527b2526391ef8e507bd2b303039ed0003de0f5110e8a86cb23e85d2b5a3d0d991c39c90df1c08e04f5cc8a96547df13f68476f740b6deb32d5617a4728e8393511c7dcc57\",\"hmac\":\"94a1979eaa868e11c65a47aa1f0b05bd6f16df2311f30829712aa91d8666a9fe\",\"iv\":\"efdab7d1213c1bcae0da0db9b9c10d74\"}","silent":true,"topic":"19CA6E39-0FCC-4F3D-A9BA-9F618154CFE4","type":"pub"}

        printf(">>> %s\n", nlohmann::json(subscriptionMessage).dump().c_str());
    }


    void SessionManager::sendAckMessage(const std::string& topic)
    {
        // ack
        WalletConnect::SocketMessage ackMessage{ topic, "ack", "", true };
        m_ServerConnexion->send(nlohmann::json(ackMessage).dump());
        printf(">>> ack message envoyé %s\n", nlohmann::json(ackMessage).dump().c_str());
    }

    void SessionManager::WaitMessage()
    {
        std::chrono::time_point<std::chrono::high_resolution_clock> time2;
        while (m_ServerConnexion->getReadyState() != easywsclient::WebSocket::CLOSED) {
            easywsclient::WebSocket::pointer wsp = &*m_ServerConnexion; // <-- because a unique_ptr cannot be copied into a lambda
            m_ServerConnexion->poll();
            m_ServerConnexion->dispatch([=](const std::string& message) {

                printf("Message reçu crypté>>> %s\n", message.c_str());

                nlohmann::json response(nlohmann::json::parse(message));

                // conversion: json -> WalletConnect::SocketMessage
                WalletConnect::SocketMessage socketMessage = response.get<WalletConnect::SocketMessage>();
                
                nlohmann::json payloadMessage = nlohmann::json::parse(socketMessage.payload);

                WalletConnect::EncryptionPayload payload = payloadMessage.get<WalletConnect::EncryptionPayload>();

                std::transform(payload.data.begin(), payload.data.end(), payload.data.begin(),
                    [](unsigned char c) { return std::toupper(c); });
                std::transform(payload.iv.begin(), payload.iv.end(), payload.iv.begin(),
                    [](unsigned char c) { return std::toupper(c); });


                jsonrpcpp::entity_ptr entity =
                    jsonrpcpp::Parser::do_parse(wrapper::crypto::aes256decrypt(m_ClientSession.GetKeyArray(), WalletConnect::hexToASCII(payload.data), WalletConnect::hexToASCII(payload.iv)));
                if (entity)
                {
                    if(entity->is_request())
                    {
                        jsonrpcpp::Request request = jsonrpcpp::Request(entity->to_json());
                        if (request.method() == "wc_sessionUpdate")
                        {
                            m_IsConnexionApprouved = request.params().get(0)["approved"];
                            if(!m_IsConnexionApprouved)
                            {
                                wsp->close();
                                OnConnexionClosed();
                            }
                        }
                        printf(" Message (request) reçu >>> %s\n", request.to_json().dump().c_str());
                    }
                    else if(entity->is_response())
                    {
                        jsonrpcpp::Response response = jsonrpcpp::Response(entity->to_json());
                        if(response.result().contains("approved"))
                        {
                            OnConnexionApproved();

                            for (std::string address : response.result()["accounts"]) 
                            {
                                m_ClientSession.AddAccount(address);
                            }
                            m_ClientSession.SetChainID(response.result()["chainId"]);
                            m_ClientSession.SetDappMeta(response.result()["peerMeta"]["description"], response.result()["peerMeta"]["url"], response.result()["peerMeta"]["icons"], response.result()["peerMeta"]["name"]);
                            
                        }
                        sendAckMessage(socketMessage.topic);
                        printf(" Message (response) reçu >>> %s\n", response.to_json().dump().c_str());
                    }
                }

                // nlohmann::json messageDecrypte(nlohmann::json::parse(wrapper::crypto::aes256decrypt(m_ClientSession.GetKeyArray(), WalletConnect::hexToASCII(payload.data), WalletConnect::hexToASCII(payload.iv))));
                // jsonrpcpp::Request reponse = jsonrpcpp::Request(nlohmann::json::parse(wrapper::crypto::aes256decrypt(m_ClientSession.GetKeyArray(), WalletConnect::hexToASCII(payload.data), WalletConnect::hexToASCII(payload.iv))));
                
                // nlohmann::json result;
                // if (reponse.method() == "wc_sessionUpdate")
                // {
                //     if (reponse.params().is_array())
                //     {
                //         m_IsConnexionApprouved = reponse.params().get(0)["approved"];
                //         if(!m_IsConnexionApprouved)
                //             wsp->close();
                //     }
                // }

                
                // printf(" Message reçu >>> %s\n", result.dump().c_str());
                // printf(" Message reçu >>> %s\n", messageDecrypte.dump().c_str());
                // printf(" Message reçu >>> %s\n", reponse.to_json().dump().c_str());

                OnMessageReceived(message);
            });
            time2 = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(time2 - m_Start);
            if(duration.count() > 120 && !m_IsConnexionApprouved)
            {
                m_ServerConnexion->close();
                InitialiseClientSession();
            }
        }
    }



    void SessionManager::SendPublicationMessage(const std::string& method, const nlohmann::json& peerMeta)
    {
        wrapper::RequestWrapper payloadMessage(method, jsonrpcpp::Parameter("chainId", 1, "peerMeta", peerMeta, "peerId", m_ClientSession.GetPeerID()));
        //{"id":"1", "jsonrpc" : "2.0", "method" : "wc_sessionRequest", "params" : [{"chainId":1,"peerId":"73a0e161-5e42-4b60-bb6d-4d775e8e05d6","peerMeta":{"description":"Premiere connexion a elrond avec le plugin Unreal Engine","icons":["https://elrondpandas.art/assets/img/favicon/favicon-32x32.png"],"name":"Elrond Panda","url":"https://elrondpandas.art/"}}]}

        printf(" Message envoyé >>> %s\n", payloadMessage.to_json().dump().c_str());

        // Prep keys, not part of performance test
        // calcul de chiffre alÈatoire
        std::default_random_engine re(std::chrono::system_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<int> distrib2{ 0, 255 };
        std::vector<uint8_t> IVKeyArray;
        IVKeyArray.resize(16);
        for (short i = 0; i < 16; i++)
        {
            short randomNumber = distrib2(re);
            IVKeyArray[i] = (randomNumber);
        }
        std::string IVString(IVKeyArray.begin(), IVKeyArray.end());


        std::string messageACrypter(payloadMessage.to_json().dump());
        // message cryptÈ 
        std::vector<uint8_t> messageCrypte = wrapper::crypto::aes256crypt(m_ClientSession.GetKeyArray(), messageACrypter, IVString);

        std::string messageCrypteString(messageCrypte.begin(), messageCrypte.end());
        std::string messageEtIV(messageCrypte.begin(), messageCrypte.end());
        messageEtIV = messageEtIV + IVString;

        std::string messageCrypteHexa(string_to_hex(messageCrypteString));
        std::string IVHexa(string_to_hex(IVString));
        std::string messageCrypteHexaF(messageCrypteHexa.c_str());
        std::string ivHex(IVHexa.c_str());

        std::transform(messageCrypteHexaF.begin(), messageCrypteHexaF.end(), messageCrypteHexaF.begin(),
            [](unsigned char c) { return std::tolower(c); });
        std::transform(ivHex.begin(), ivHex.end(), ivHex.begin(),
            [](unsigned char c) { return std::tolower(c); });

        std::string hmac = wrapper::crypto::hmacsha256(m_ClientSession.GetKeyArray(), messageEtIV);
        std::string hmacHex = string_to_hex(hmac);
        std::string hmacHexF(hmacHex.c_str());

        std::transform(hmacHexF.begin(), hmacHexF.end(), hmacHexF.begin(),
            [](unsigned char c) { return std::tolower(c); });


        WalletConnect::EncryptionPayload payloadMessageCrypte;
        payloadMessageCrypte.iv = ivHex;
        payloadMessageCrypte.hmac = hmacHexF;
        payloadMessageCrypte.data = messageCrypteHexaF;

        nlohmann::json jpayloadMessageCrypte = payloadMessageCrypte;
        
        std::string payloadMessageCrypteFinal(jpayloadMessageCrypte.dump());

        WalletConnect::SocketMessage finalData{ m_ClientSession.GetTopic(), "pub", payloadMessageCrypteFinal, true };
        m_ServerConnexion->send(nlohmann::json(finalData).dump());
        // //{"topic":"25e48c19-dc6f-4d6a-9f79-be3d22ef747a","type":"pub","payload":"{\"iv":"3a503ccf03f9f2639708c5c5028021a4","hmac":"930a5d29534794130bc19321e3448108acdcf7224fdd5ae510e5304b23ebea2a","data":"98506a14ca36f718179bd5604eb5e6070b71bd2f224e0e02e5d554623b9a1d8f28ce30f82ad5c0d207f4a1e9c9c053cf6e5b51aaa22b732b61043d9361a6c22edc79e727708af20ad4972aa33f600f8a52900ab3445ac2dc56a70e072082b272abdb46f7ce89f12fa7b1adbc0e980410b8a57866f2f0755945ffd226fb4e9e1df4777dd2d606053cbd48c8c4f845409a4b1fd6c731af46c6694d1fdb2e1e09c13333e3e16083aaab5a16379d5a9694bbfb7d40612cc00b95eb506f2d7affa8198ae927591876f27fd489ad3d0be4ad154f163420d5da11a19cd972627d9d53569a67d54bb0ff654778f8bcd51a4e765d4d2d9d9f1b730efc78ebfb93e0709e780f0bffe8f263106e046d9703a6ad7fbd14763ad8a29535b8bc92bbb3acbe130a79decc90f1ecd32ab0560a3ff19601bab090ca8d141e46da84b34b9b451a9252df4651fd5863108b1a0405a73b4ae9c1d505ce0d1e0d2fe0a5c18f97276f8d9653804a2c59304fcefef9be41baf66bf0"}", "silent":true}
        printf(">>> %s\n", nlohmann::json(finalData).dump().c_str());

        //{"payload":"{\"data\":\"712abaea0a7017152bd4723706d10ace40306739ca7f0ce84613d44061d260f7ac2e6e06dce93eddbaee4191dd05b9e5a034b63a1988455b38abe5274a45ed29c944c426bacad0993fe5680b0979f408c7a6549e8ce0ad3fe9b680259c4adc64a045e17f8f0cdab3e5c5174c29507334da4b9785e1df98e7dc232788a04918c11be7f48f84a32b3b3836c7fb4c3b65244fe9781a1d1db1bce67dc12c6889c93db04db91d08f827d25dbafe48cb34738b90168414a64ce70b4fae49039da142aa382a280820d0e58b9ab0fd5d474b40c2622a891daf71c071ef4a4e23e30ea50a37ba647fc0f3df77f3cef8aac442ce8db0877e992738b6633348f9916c9680b43a9e30c16f2959f8c15a04ca0cba2b2b566edf4f9ae86aab8bc9f4b6b178b39ec52393ed4bd01770c64e2d4d086c6c4cac118e7224d847c0d91963e4e54b8646e063c0356b47feff7597184b936115c8e07641a230faaca9a75090d10e8705af03c2162799e33c51407d685e50472810\",\"hmac\":\"3b57da1d5f27bcc40fb98dfa09f00a53399ef8ec9ea44b80a01a4698d848774d\",\"iv\":\"c3b640baa72ede6d7a20a39a5b10a288\"}","silent":true,"topic":"FE04B3B9-F58C-4F75-805E-FBC09CED78FB","type":"pub"}
    }

    void SessionManager::SendPublicationMessage(const std::string& method, const std::string& peerMeta)
    {
        // calcul de chiffre alÈatoire
        std::default_random_engine re(std::chrono::system_clock::now().time_since_epoch().count());

        std::uniform_int_distribution<int> distrib2{ 0, 255 };

        // Id a changer
        nlohmann::json jPeerMeta = peerMeta;
        wrapper::RequestWrapper payloadMessage(1, method, jsonrpcpp::Parameter("chainId", 1, "peerMeta", jPeerMeta, "peerId", m_ClientSession.GetPeerID()));
        //{"id":"1", "jsonrpc" : "2.0", "method" : "wc_sessionRequest", "params" : [{"chainId":1,"peerId":"73a0e161-5e42-4b60-bb6d-4d775e8e05d6","peerMeta":{"description":"Premiere connexion a elrond avec le plugin Unreal Engine","icons":["https://elrondpandas.art/assets/img/favicon/favicon-32x32.png"],"name":"Elrond Panda","url":"https://elrondpandas.art/"}}]}

        // Prep keys, not part of performance test
        std::vector<uint8_t> IVKeyArray;
        IVKeyArray.resize(16);
        for (short i = 0; i < 16; i++)
        {
            short randomNumber = distrib2(re);
            IVKeyArray[i] = (randomNumber);
        }
        std::string IVString(IVKeyArray.begin(), IVKeyArray.end());


        std::string messageACrypter(payloadMessage.to_json().dump());
        // message cryptÈ 
        std::vector<uint8_t> messageCrypte = wrapper::crypto::aes256crypt(m_ClientSession.GetKeyArray(), messageACrypter, IVString);

        std::string messageCrypteString(messageCrypte.begin(), messageCrypte.end());
        std::string messageEtIV(messageCrypte.begin(), messageCrypte.end());
        messageEtIV = messageEtIV + IVString;



        std::string messageCrypteHexa(WalletConnect::string_to_hex(messageCrypteString));
        std::string IVHexa(WalletConnect::string_to_hex(IVString));
        std::string messageCrypteHexaF(messageCrypteHexa.c_str());
        std::string ivHex(IVHexa.c_str());

        std::transform(messageCrypteHexaF.begin(), messageCrypteHexaF.end(), messageCrypteHexaF.begin(),
            [](unsigned char c) { return std::tolower(c); });
        std::transform(ivHex.begin(), ivHex.end(), ivHex.begin(),
            [](unsigned char c) { return std::tolower(c); });

        std::string hmac = wrapper::crypto::hmacsha256(m_ClientSession.GetKeyArray(), messageEtIV);
        std::string hmacHex = string_to_hex(hmac);
        std::string hmacHexF(hmacHex.c_str());

        std::transform(hmacHexF.begin(), hmacHexF.end(), hmacHexF.begin(),
            [](unsigned char c) { return std::tolower(c); });


        WalletConnect::EncryptionPayload payloadMessageCrypte;
        payloadMessageCrypte.iv = ivHex;
        payloadMessageCrypte.hmac = hmacHexF;
        payloadMessageCrypte.data = messageCrypteHexaF;

        nlohmann::json jpayloadMessageCrypte = payloadMessageCrypte;
        
        std::string payloadMessageCrypteFinal(jpayloadMessageCrypte.dump());

        WalletConnect::SocketMessage finalData{ m_ClientSession.GetTopic(), "pub", payloadMessageCrypteFinal, true };
        m_ServerConnexion->send(nlohmann::json(finalData).dump());
        // //{"topic":"25e48c19-dc6f-4d6a-9f79-be3d22ef747a","type":"pub","payload":"{\"iv":"3a503ccf03f9f2639708c5c5028021a4","hmac":"930a5d29534794130bc19321e3448108acdcf7224fdd5ae510e5304b23ebea2a","data":"98506a14ca36f718179bd5604eb5e6070b71bd2f224e0e02e5d554623b9a1d8f28ce30f82ad5c0d207f4a1e9c9c053cf6e5b51aaa22b732b61043d9361a6c22edc79e727708af20ad4972aa33f600f8a52900ab3445ac2dc56a70e072082b272abdb46f7ce89f12fa7b1adbc0e980410b8a57866f2f0755945ffd226fb4e9e1df4777dd2d606053cbd48c8c4f845409a4b1fd6c731af46c6694d1fdb2e1e09c13333e3e16083aaab5a16379d5a9694bbfb7d40612cc00b95eb506f2d7affa8198ae927591876f27fd489ad3d0be4ad154f163420d5da11a19cd972627d9d53569a67d54bb0ff654778f8bcd51a4e765d4d2d9d9f1b730efc78ebfb93e0709e780f0bffe8f263106e046d9703a6ad7fbd14763ad8a29535b8bc92bbb3acbe130a79decc90f1ecd32ab0560a3ff19601bab090ca8d141e46da84b34b9b451a9252df4651fd5863108b1a0405a73b4ae9c1d505ce0d1e0d2fe0a5c18f97276f8d9653804a2c59304fcefef9be41baf66bf0"}", "silent":true}
        printf(">>> %s\n", nlohmann::json(finalData).dump().c_str());
        //{"payload":"{\"data\":\"712abaea0a7017152bd4723706d10ace40306739ca7f0ce84613d44061d260f7ac2e6e06dce93eddbaee4191dd05b9e5a034b63a1988455b38abe5274a45ed29c944c426bacad0993fe5680b0979f408c7a6549e8ce0ad3fe9b680259c4adc64a045e17f8f0cdab3e5c5174c29507334da4b9785e1df98e7dc232788a04918c11be7f48f84a32b3b3836c7fb4c3b65244fe9781a1d1db1bce67dc12c6889c93db04db91d08f827d25dbafe48cb34738b90168414a64ce70b4fae49039da142aa382a280820d0e58b9ab0fd5d474b40c2622a891daf71c071ef4a4e23e30ea50a37ba647fc0f3df77f3cef8aac442ce8db0877e992738b6633348f9916c9680b43a9e30c16f2959f8c15a04ca0cba2b2b566edf4f9ae86aab8bc9f4b6b178b39ec52393ed4bd01770c64e2d4d086c6c4cac118e7224d847c0d91963e4e54b8646e063c0356b47feff7597184b936115c8e07641a230faaca9a75090d10e8705af03c2162799e33c51407d685e50472810\",\"hmac\":\"3b57da1d5f27bcc40fb98dfa09f00a53399ef8ec9ea44b80a01a4698d848774d\",\"iv\":\"c3b640baa72ede6d7a20a39a5b10a288\"}","silent":true,"topic":"FE04B3B9-F58C-4F75-805E-FBC09CED78FB","type":"pub"}
    }

    void SessionManager::creationFichierQrCode()
    {
        OnCreationFichierQrCode(m_ClientSession.GetQrCodeUrl().c_str());
        OnCreationMaiarLink(m_ClientSession.GetMaiarWalletLink());
    }

}
