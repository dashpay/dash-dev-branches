// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_PROVIDERTRANSACTIONTESTS_H
#define BITCOIN_QT_TEST_PROVIDERTRANSACTIONTESTS_H

#include <QObject>

namespace interfaces {
class Node;
} // namespace interfaces

class ProviderTransactionTests : public QObject
{
    Q_OBJECT

public:
    explicit ProviderTransactionTests(interfaces::Node& node) :
        m_node(node)
    {
    }

private Q_SLOTS:
    void transactionTypeSettingPersistence_data();
    void transactionTypeSettingPersistence();
    void providerTransactionHistory();

private:
    interfaces::Node& m_node;
};

#endif // BITCOIN_QT_TEST_PROVIDERTRANSACTIONTESTS_H
