#include "provider/data/data_transaction.h"

TransactionStatus::TransactionStatus(std::string status) :
    m_status(std::move(status)){}

bool TransactionStatus::operator ==(TransactionStatus const& txStatus)
{
    return this->m_status == txStatus.m_status;
}

bool TransactionStatus::isPending() const
{
    return m_status == "pending";
}

bool TransactionStatus::isExecuted() const
{
    return (m_status == "executed") || isSuccessful() || isInvalid();
}

bool TransactionStatus::isSuccessful() const
{
    return (m_status == "success") || (m_status == "successful");
}

bool TransactionStatus::isFailed() const
{
    return (m_status == "fail") || (m_status == "failed") || (m_status == "unsuccessful") || isInvalid();
}

bool TransactionStatus::isInvalid() const
{
    return m_status == "invalid";
}
