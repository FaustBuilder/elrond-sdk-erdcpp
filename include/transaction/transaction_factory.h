#ifndef ERD_TRANSACTION_FACTORY_H
#define ERD_TRANSACTION_FACTORY_H

#include "gas_estimator.h"
#include "token_payment.h"
#include "itransaction_builder.h"

class TransactionFactory
{
public:
    explicit TransactionFactory(const NetworkConfig &networkConfig);

    ITransactionBuilder &createEGLDTransfer(uint64_t nonce,
                                            BigUInt value,
                                            Address sender,
                                            Address receiver,
                                            uint64_t gasPrice,
                                            std::string data);

    ITokenTransactionBuilder &createESDTTransfer(TokenPayment tokenPayment,
                                                 uint64_t nonce,
                                                 Address sender,
                                                 Address receiver,
                                                 uint64_t gasPrice);

private:
    std::string m_chainID;
    GasEstimator m_gasEstimator;
};

#endif //ERD_TRANSACTION_FACTORY_H
