#include "transaction/transaction.h"

#include "hex.h"
#include "errors.h"
#include "params.h"
#include "jsonwrapper.h"
#include "cryptosignwrapper.h"

#define OPTIONS_SIGN_TX_HASH_MASK 1U
#define VERSION_SIGN_TX_HASH 2U

namespace internal
{
template<typename T>
void setJsonValueIfNotNull(wrapper::json::OrderedJson &json, std::string const &key, std::shared_ptr<T> const &val)
{
    if (val != nullptr)
        json.set(key, *val);
}

template<typename T>
void getJsonValueIfNotNull(wrapper::json::OrderedJson const &json, std::string const &key, std::shared_ptr<T> &val)
{
    if (json.contains(key))
    {
        T const tmpVal = json.at<T>(key);
        val = std::make_shared<T>(tmpVal);
    }
}

bool shouldSignHash(Transaction const &tx)
{
    return (tx.m_options != nullptr) &&
           (tx.m_version >= VERSION_SIGN_TX_HASH) &&
           (*tx.m_options & OPTIONS_SIGN_TX_HASH_MASK);
}

std::string getSerializedTxMsg(Transaction tx, bool const withSignature)
{
    if (!withSignature)
    {
        tx.m_signature = nullptr;
    }

    std::string txSerialized = tx.serialize();

    if (shouldSignHash(tx))
    {
        txSerialized = wrapper::crypto::sha3Keccak(txSerialized);
    }

    return txSerialized;
}

template<typename T>
inline bool pointersHaveSameValue(std::shared_ptr<T> v1, std::shared_ptr<T> v2)
{
    if (v1 == nullptr && v2 == nullptr)
    {
        return true;
    }
    if (v1 != nullptr && v2 != nullptr)
    {
        return *v1.get() == *v2.get();
    }

    return false;
}

}

Transaction::Transaction(
        uint64_t const &nonce,
        BigUInt value,
        Address const &receiver,
        Address const &sender,
        std::shared_ptr<bytes> receiverUserName,
        std::shared_ptr<bytes> senderUserName,
        uint64_t const &gasPrice,
        uint64_t const &gasLimit,
        std::shared_ptr<bytes> data,
        std::shared_ptr<std::string> signature,
        std::string chainID,
        uint64_t const &version,
        std::shared_ptr<uint32_t> options) :
        m_nonce(nonce),
        m_value(std::move(value)),
        m_receiver(new Address(receiver)),
        m_sender(new Address(sender)),
        m_receiverUserName(std::move(receiverUserName)),
        m_senderUserName(std::move(senderUserName)),
        m_gasPrice(gasPrice),
        m_gasLimit(gasLimit),
        m_data(std::move(data)),
        m_signature(std::move(signature)),
        m_chainID(std::move(chainID)),
        m_version(version),
        m_options(std::move(options))
{}

Transaction::Transaction() :
        m_nonce(DEFAULT_NONCE),
        m_value(DEFAULT_VALUE),
        m_receiver(DEFAULT_RECEIVER),
        m_sender(DEFAULT_SENDER),
        m_receiverUserName(DEFAULT_RECEIVER_NAME),
        m_senderUserName(DEFAULT_SENDER_NAME),
        m_gasPrice(DEFAULT_GAS_PRICE),
        m_gasLimit(DEFAULT_GAS_LIMIT),
        m_data(DEFAULT_DATA),
        m_signature(DEFAULT_SIGNATURE),
        m_chainID(DEFAULT_CHAIN_ID),
        m_version(DEFAULT_VERSION),
        m_options(DEFAULT_OPTIONS)
{}


bool Transaction::operator==(const Transaction &rhs) const
{
    return (this->m_nonce == rhs.m_nonce &&
            this->m_value == rhs.m_value &&
            internal::pointersHaveSameValue(this->m_sender, rhs.m_sender) &&
            internal::pointersHaveSameValue(this->m_receiver, rhs.m_receiver) &&
            internal::pointersHaveSameValue(this->m_senderUserName, rhs.m_senderUserName) &&
            internal::pointersHaveSameValue(this->m_receiverUserName, rhs.m_receiverUserName) &&
            this->m_gasPrice == rhs.m_gasPrice &&
            this->m_gasLimit == rhs.m_gasLimit &&
            internal::pointersHaveSameValue(this->m_data, rhs.m_data) &&
            internal::pointersHaveSameValue(this->m_signature, rhs.m_signature) &&
            this->m_chainID == rhs.m_chainID &&
            this->m_version == rhs.m_version &&
            internal::pointersHaveSameValue(this->m_options, rhs.m_options)
    );
}

bool Transaction::operator!=(const Transaction &rhs) const
{
    return !(*this == rhs);
}

void Transaction::sign(Signer const &signer)
{
    std::string const txSerialized = internal::getSerializedTxMsg(*this, false);
    std::string const tmpSign = signer.getSignature(txSerialized);
    std::string const signature = util::stringToHex(tmpSign);

    m_signature.reset(new std::string(signature));
}

bool Transaction::verify()
{
    if (m_signature == nullptr) throw std::runtime_error(ERROR_MSG_SIGNATURE);
    if (m_sender == nullptr) throw std::runtime_error(ERROR_MSG_SENDER);

    std::string const txSerialized = internal::getSerializedTxMsg(*this, false);

    return Signer::verify(util::hexToString(*m_signature), txSerialized, *m_sender);
}

std::string Transaction::serialize() const
{
    if (m_receiver == nullptr) throw std::invalid_argument(ERROR_MSG_RECEIVER);
    if (m_sender == nullptr) throw std::invalid_argument(ERROR_MSG_SENDER);

    wrapper::json::OrderedJson json;

    json.set(TX_NONCE, m_nonce);
    json.set(TX_VALUE, m_value.getValue());
    json.set(TX_RECEIVER, (*m_receiver).getBech32Address());
    json.set(TX_SENDER, (*m_sender).getBech32Address());
    internal::setJsonValueIfNotNull(json, TX_RECEIVER_NAME, m_receiverUserName);
    internal::setJsonValueIfNotNull(json, TX_SENDER_NAME, m_senderUserName);
    json.set(TX_GAS_PRICE, m_gasPrice);
    json.set(TX_GAS_LIMIT, m_gasLimit);
    internal::setJsonValueIfNotNull(json, TX_DATA, m_data);
    internal::setJsonValueIfNotNull(json, TX_SIGNATURE, m_signature);
    json.set(TX_CHAIN_ID, m_chainID);
    json.set(TX_VERSION, m_version);
    internal::setJsonValueIfNotNull(json, TX_OPTIONS, m_options);

    return json.serialize();
}

void Transaction::deserialize(std::string const &serializedTransaction)
{
    wrapper::json::OrderedJson json;

    try
    {
        json.deserialize(serializedTransaction);
    }
    catch (std::invalid_argument const &err)
    {
        throw err;
    }

    if (!json.contains(TX_NONCE)) throw std::invalid_argument(ERROR_MSG_NONCE);
    if (!json.contains(TX_VALUE)) throw std::invalid_argument(ERROR_MSG_VALUE);
    if (!json.contains(TX_RECEIVER)) throw std::invalid_argument(ERROR_MSG_RECEIVER);
    if (!json.contains(TX_SENDER)) throw std::invalid_argument(ERROR_MSG_SENDER);
    if (!json.contains(TX_GAS_PRICE)) throw std::invalid_argument(ERROR_MSG_GAS_PRICE);
    if (!json.contains(TX_GAS_LIMIT)) throw std::invalid_argument(ERROR_MSG_GAS_LIMIT);
    if (!json.contains(TX_CHAIN_ID)) throw std::invalid_argument(ERROR_MSG_CHAIN_ID);
    if (!json.contains(TX_VERSION)) throw std::invalid_argument(ERROR_MSG_VERSION);

    m_nonce = json.at<uint64_t>(TX_NONCE);
    m_value = BigUInt(json.at<std::string>(TX_VALUE));
    m_receiver.reset(new Address(json.at<std::string>(TX_RECEIVER)));
    m_sender.reset(new Address(json.at<std::string>(TX_SENDER)));
    m_gasPrice = json.at<uint64_t>(TX_GAS_PRICE);
    m_gasLimit = json.at<uint64_t>(TX_GAS_LIMIT);
    m_chainID = json.at<std::string>(TX_CHAIN_ID);
    m_version = json.at<uint64_t>(TX_VERSION);

    internal::getJsonValueIfNotNull(json, TX_DATA, m_data);
    internal::getJsonValueIfNotNull(json, TX_SIGNATURE, m_signature);
    internal::getJsonValueIfNotNull(json, TX_RECEIVER_NAME, m_receiverUserName);
    internal::getJsonValueIfNotNull(json, TX_SENDER_NAME, m_senderUserName);
    internal::getJsonValueIfNotNull(json, TX_OPTIONS, m_options);
}
