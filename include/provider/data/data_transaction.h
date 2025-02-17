#ifndef ERD_PROXY_DATA_TRANSACTION_H
#define ERD_PROXY_DATA_TRANSACTION_H

#include <string>

// Also see ERDJS implementation:
// https://github.com/ElrondNetwork/elrond-sdk-erdjs/blob/5c10d7d69dbc424464909398d0874684b59cb2c4/src/transaction.ts#L455
class TransactionStatus
{
public:
    explicit TransactionStatus(std::string status);

    bool operator ==(TransactionStatus const& txStatus);

    bool isPending() const;

    bool isExecuted() const;

    bool isSuccessful() const;

    bool isFailed() const;

    bool isInvalid() const;

private:
    std::string m_status;
};

#endif

