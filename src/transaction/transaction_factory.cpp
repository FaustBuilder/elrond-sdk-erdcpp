#include <utility>

#include "transaction/payload_builder.h"
#include "transaction/transaction_factory.h"
#include "transaction/transaction_builders.h"
#include "transaction/transaction_builder_input.h"

TransactionFactory::TransactionFactory(const NetworkConfig &networkConfig) :
        m_gasEstimator(networkConfig), m_chainID(networkConfig.chainId)
{}

std::unique_ptr<ITransactionBuilder>
TransactionFactory::createEGLDTransfer(uint64_t nonce,
                                       BigUInt value,
                                       Address sender,
                                       Address receiver,
                                       uint64_t gasPrice,
                                       std::string data)
{
    TransactionEGLDTransferBuilder builder({nonce,
                                            std::move(value),
                                            std::move(sender),
                                            std::move(receiver),
                                            std::move(data),
                                            gasPrice,
                                            m_chainID,
                                            m_gasEstimator});
    return std::make_unique<TransactionEGLDTransferBuilder>(builder);
}

std::unique_ptr<ITransactionBuilder> TransactionFactory::createESDTIssue(uint64_t nonce,
                                                                         Address sender,
                                                                         uint64_t const &gasPrice,
                                                                         std::string const &token,
                                                                         std::string const &ticker,
                                                                         BigUInt const &initialSupply,
                                                                         uint32_t const &numOfDecimals,
                                                                         ESDTProperties const &esdtProperties)
{
    std::string data = ESDTIssuePayloadBuilder(token)
            .setTicker(ticker)
            .setInitialSupply(initialSupply)
            .setNumOfDecimals(numOfDecimals)
            .withProperties(esdtProperties)
            .build();

    TransactionEGLDTransferBuilder builder({nonce,
                                            BigUInt(ESDT_ISSUANCE_VALUE),
                                            std::move(sender),
                                            ESDT_ISSUANCE_ADDRESS,
                                            std::move(data),
                                            gasPrice,
                                            m_chainID,
                                            m_gasEstimator,
                                            ESDT_ISSUANCE_GAS_LIMIT});

    return std::make_unique<TransactionEGLDTransferBuilder>(builder);
}

std::unique_ptr<ITokenTransactionBuilder>
TransactionFactory::createESDTTransfer(TokenPayment tokenPayment,
                                       uint64_t nonce,
                                       Address sender,
                                       Address receiver,
                                       uint64_t gasPrice)
{
    TransactionESDTBuilder builder({nonce,
                                    BigUInt(0),
                                    std::move(sender),
                                    std::move(receiver),
                                    "",
                                    gasPrice,
                                    m_chainID,
                                    m_gasEstimator},
                                   std::move(tokenPayment));
    return std::make_unique<TransactionESDTBuilder>(builder);
}

std::unique_ptr<ITokenTransactionBuilder>
TransactionFactory::createESDTNFTTransfer(TokenPayment tokenPayment,
                                          uint64_t nonce,
                                          Address sender,
                                          Address destination,
                                          uint64_t gasPrice)
{
    TransactionESDTNFTBuilder builder({nonce,
                                       BigUInt(0),
                                       std::move(sender),
                                       std::move(destination),
                                       "",
                                       gasPrice,
                                       m_chainID,
                                       m_gasEstimator},
                                      std::move(tokenPayment));

    return std::make_unique<TransactionESDTNFTBuilder>(builder);
}

std::unique_ptr<ITokenTransactionBuilder>
TransactionFactory::createMultiESDTNFTTransfer(std::vector<TokenPayment> tokenPayments,
                                               uint64_t nonce,
                                               Address sender,
                                               Address destination,
                                               uint64_t gasPrice)
{
    TransactionMultiESDTNFTBuilder builder({nonce,
                                            BigUInt(0),
                                            std::move(sender),
                                            std::move(destination),
                                            "",
                                            gasPrice,
                                            m_chainID,
                                            m_gasEstimator},
                                           std::move(tokenPayments));

    return std::make_unique<TransactionMultiESDTNFTBuilder>(builder);
}
