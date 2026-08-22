// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/masternodeoperationrunner.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <QMetaObject>
#include <QThread>

#include <exception>
#include <mutex>
#include <optional>
#include <utility>

MasternodeOperationRunner::MasternodeOperationRunner(interfaces::EVO& evo, interfaces::Wallet& wallet,
                                                     QObject* parent) :
    QObject(parent),
    m_evo(evo),
    m_wallet(wallet),
    m_thread(new QThread(this)),
    m_worker(new QObject())
{
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    m_thread->start();
    QMetaObject::invokeMethod(m_worker, [] { util::ThreadRename("qt-providertx"); });
}

MasternodeOperationRunner::~MasternodeOperationRunner()
{
    shutdown();
}

template <typename Result, typename Operation, typename Callback>
bool MasternodeOperationRunner::run(Operation operation, Callback callback)
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (m_busy || m_shutdown || !m_thread->isRunning()) return false;
    m_busy = true;
    struct SharedResult {
        std::mutex mutex;
        std::optional<Result> value;
    };
    auto result{std::make_shared<SharedResult>()};
    m_pending_delivery = [this, result, callback = std::move(callback)]() mutable {
        std::optional<Result> completed;
        {
            const std::lock_guard<std::mutex> lock{result->mutex};
            if (!result->value) return;
            completed.emplace(std::move(*result->value));
            result->value.reset();
        }
        m_busy = false;
        callback(std::move(*completed));
    };
    const bool dispatched{QMetaObject::invokeMethod(
        m_worker, [this, operation = std::move(operation), result]() mutable {
            std::optional<Result> completed;
            try {
                completed.emplace(operation());
            } catch (const std::exception& e) {
                completed.emplace(interfaces::ProviderTxError{interfaces::ProviderTxErrorCode::INTERNAL_ERROR,
                                                              Untranslated(e.what()), {}, std::nullopt});
            } catch (...) {
                completed.emplace(interfaces::ProviderTxError{interfaces::ProviderTxErrorCode::INTERNAL_ERROR,
                                                              Untranslated("provider transaction operation failed"),
                                                              {}, std::nullopt});
            }
            {
                const std::lock_guard<std::mutex> lock{result->mutex};
                result->value.emplace(std::move(*completed));
            }
            const bool queued{QMetaObject::invokeMethod(this, [this] {
                auto delivery{std::move(m_pending_delivery)};
                if (delivery) delivery();
            })};
            Q_ASSERT(queued);
            Q_UNUSED(queued);
        })};
    if (!dispatched) {
        m_pending_delivery = {};
        m_busy = false;
        return false;
    }
    return true;
}

void MasternodeOperationRunner::shutdown()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (m_shutdown) return;
    m_shutdown = true;

    if (m_thread->isRunning()) {
        // This blocking call is queued after any pending operation. It keeps
        // the worker event loop alive until that operation has produced its
        // result, including when shutdown starts immediately after dispatch.
        const bool drained{QMetaObject::invokeMethod(m_worker, [] {}, Qt::BlockingQueuedConnection)};
        Q_ASSERT(drained);
        Q_UNUSED(drained);
        m_thread->quit();
        m_thread->wait();
    }

    // Move before invocation: the callback may destroy the runner, and the
    // function object must not erase itself while it is executing.
    auto delivery{std::move(m_pending_delivery)};
    if (delivery) delivery();
}

bool MasternodeOperationRunner::registerMasternode(interfaces::ProviderRegistrationRequest request,
                                                   SubmissionCallback callback)
{
    return run<SubmissionResult>(
        [this, request = std::move(request)] { return m_evo.registerMasternode(m_wallet, request); },
        std::move(callback));
}

bool MasternodeOperationRunner::prepareMasternodeRegistration(interfaces::ProviderRegistrationRequest request,
                                                              PrepareCallback callback)
{
    return run<PrepareResult>(
        [this, request = std::move(request)] { return m_evo.prepareMasternodeRegistration(m_wallet, request); },
        std::move(callback));
}

bool MasternodeOperationRunner::submitMasternodeRegistration(CTransactionRef transaction,
                                                             std::vector<unsigned char> signature,
                                                             SubmissionCallback callback)
{
    return run<SubmissionResult>(
        [this, transaction = std::move(transaction), signature = std::move(signature)] {
            return m_evo.submitMasternodeRegistration(m_wallet, transaction, signature);
        },
        std::move(callback));
}

bool MasternodeOperationRunner::updateMasternodeService(interfaces::ProviderUpdateServiceRequest request,
                                                        SubmissionCallback callback)
{
    return run<SubmissionResult>(
        [this, request = std::move(request)] { return m_evo.updateMasternodeService(m_wallet, request); },
        std::move(callback));
}

bool MasternodeOperationRunner::updateMasternodeRegistrar(interfaces::ProviderUpdateRegistrarRequest request,
                                                          SubmissionCallback callback)
{
    return run<SubmissionResult>(
        [this, request = std::move(request)] { return m_evo.updateMasternodeRegistrar(m_wallet, request); },
        std::move(callback));
}

bool MasternodeOperationRunner::revokeMasternode(interfaces::ProviderRevokeRequest request,
                                                 SubmissionCallback callback)
{
    return run<SubmissionResult>(
        [this, request = std::move(request)] { return m_evo.revokeMasternode(m_wallet, request); },
        std::move(callback));
}
