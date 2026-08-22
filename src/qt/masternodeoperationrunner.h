// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MASTERNODEOPERATIONRUNNER_H
#define BITCOIN_QT_MASTERNODEOPERATIONRUNNER_H

#include <interfaces/providertx.h>

#include <QObject>

#include <functional>
#include <memory>
#include <vector>

namespace interfaces {
class EVO;
class Wallet;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QThread;
QT_END_NAMESPACE

/**
 * Runs synchronous typed provider-transaction operations away from the GUI
 * thread. Parsing and presentation remain in the dialog; this class transports
 * domain requests and results without RPC method names, JSON, or wallet URIs.
 */
class MasternodeOperationRunner : public QObject
{
    Q_OBJECT

public:
    using SubmissionResult = interfaces::ProviderTxResult<interfaces::ProviderTxSubmission>;
    using PrepareResult = interfaces::ProviderTxResult<interfaces::PreparedProviderRegistration>;
    using SubmissionCallback = std::function<void(SubmissionResult)>;
    using PrepareCallback = std::function<void(PrepareResult)>;

    MasternodeOperationRunner(interfaces::EVO& evo, interfaces::Wallet& wallet, QObject* parent = nullptr);
    ~MasternodeOperationRunner() override;

    bool registerMasternode(interfaces::ProviderRegistrationRequest request, SubmissionCallback callback);
    bool prepareMasternodeRegistration(interfaces::ProviderRegistrationRequest request, PrepareCallback callback);
    bool submitMasternodeRegistration(CTransactionRef transaction, std::vector<unsigned char> signature,
                                      SubmissionCallback callback);
    bool updateMasternodeService(interfaces::ProviderUpdateServiceRequest request, SubmissionCallback callback);
    bool updateMasternodeRegistrar(interfaces::ProviderUpdateRegistrarRequest request, SubmissionCallback callback);
    bool revokeMasternode(interfaces::ProviderRevokeRequest request, SubmissionCallback callback);

    bool isBusy() const { return m_busy; }
    //! Wait for a running operation and synchronously deliver its result on the
    //! caller thread. Used during owner/app teardown so completion and resource
    //! ownership cannot disappear with a queued Qt callback.
    void shutdown();

private:
    template <typename Result, typename Operation, typename Callback>
    bool run(Operation operation, Callback callback);

    interfaces::EVO& m_evo;
    interfaces::Wallet& m_wallet;
    QThread* const m_thread;
    QObject* const m_worker;
    bool m_busy{false};
    bool m_shutdown{false};
    std::function<void()> m_pending_delivery;
};

#endif // BITCOIN_QT_MASTERNODEOPERATIONRUNNER_H
