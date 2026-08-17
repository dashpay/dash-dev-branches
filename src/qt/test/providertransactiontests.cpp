// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/providertransactiontests.h>

#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactionrecord.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <memory>
#include <optional>
#include <vector>

#include <QApplication>
#include <QComboBox>
#include <QListView>
#include <QSettings>
#include <QTableView>
#include <QTest>

using wallet::AddWallet;
using wallet::CreateMockWalletDatabase;
using wallet::CWallet;
using wallet::RemoveWallet;
using wallet::TxStateInactive;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WalletContext;
using wallet::WalletDescriptor;
using wallet::WalletRescanReserver;

namespace {

struct ExpectedRecord {
    uint256 txid;
    TransactionRecord::Type type;
    CAmount amount;
    QString label;
    QString tooltip_text;
};

CTransactionRef MakeSpecialTransaction(uint16_t type, const COutPoint& input, CAmount output_amount,
                                       const CScript& output_script)
{
    CMutableTransaction tx;
    tx.nVersion = CTransaction::SPECIAL_VERSION;
    tx.nType = type;
    tx.vin.emplace_back(input);
    tx.vout.emplace_back(output_amount, output_script);
    return MakeTransactionRef(std::move(tx));
}

std::vector<int> FindTransactionRows(const QAbstractItemModel& model, const uint256& txid)
{
    const QString hash{QString::fromStdString(txid.ToString())};
    std::vector<int> rows;
    for (int row = 0; row < model.rowCount(); ++row) {
        if (model.index(row, 0).data(TransactionTableModel::TxHashRole).toString() == hash) {
            rows.push_back(row);
        }
    }
    return rows;
}

QComboBox* FindTransactionTypeWidget(TransactionView& view)
{
    for (QComboBox* combo : view.findChildren<QComboBox*>()) {
        if (combo->findText("Masternode") >= 0) return combo;
    }
    return nullptr;
}

class WalletCleanup
{
public:
    WalletCleanup(WalletContext& context, std::shared_ptr<CWallet> wallet) :
        m_context(context),
        m_wallet(std::move(wallet))
    {
    }
    ~WalletCleanup() { RemoveWallet(m_context, m_wallet, /*load_on_start=*/std::nullopt); }

private:
    WalletContext& m_context;
    std::shared_ptr<CWallet> m_wallet;
};

class CoinJoinOptionsRestorer
{
public:
    explicit CoinJoinOptionsRestorer(interfaces::CoinJoin::Options& options) :
        m_options(options),
        m_enabled(options.isEnabled())
    {
    }
    ~CoinJoinOptionsRestorer() { m_options.setEnabled(m_enabled); }

private:
    interfaces::CoinJoin::Options& m_options;
    const bool m_enabled;
};

class TransactionTypeSettingRestorer
{
public:
    TransactionTypeSettingRestorer() :
        m_had_value(m_settings.contains("transactionType")),
        m_value(m_settings.value("transactionType"))
    {
    }
    ~TransactionTypeSettingRestorer()
    {
        if (m_had_value) {
            m_settings.setValue("transactionType", m_value);
        } else {
            m_settings.remove("transactionType");
        }
    }

private:
    QSettings m_settings;
    const bool m_had_value;
    const QVariant m_value;
};

void CheckProviderRecords(const TransactionTableModel& model, const std::vector<ExpectedRecord>& expected)
{
    for (const ExpectedRecord& record : expected) {
        const std::vector<int> rows{FindTransactionRows(model, record.txid)};
        QCOMPARE(rows.size(), size_t{1});

        const QModelIndex base{model.index(rows.front(), 0)};
        const QModelIndex type_index{model.index(rows.front(), TransactionTableModel::Type)};
        const QModelIndex address_index{model.index(rows.front(), TransactionTableModel::ToAddress)};

        QCOMPARE(base.data(TransactionTableModel::TypeRole).toInt(), static_cast<int>(record.type));
        QCOMPARE(base.data(TransactionTableModel::AmountRole).toLongLong(), record.amount);
        QCOMPARE(base.data(TransactionTableModel::AddressRole).toString(), QString{});
        QCOMPARE(base.data(TransactionTableModel::LabelRole).toString(), QString{});
        QCOMPARE(type_index.data(Qt::DisplayRole).toString(), record.label);
        QCOMPARE(address_index.data(Qt::DisplayRole).toString(), QString{"(n/a)"});

        const QString tooltip{type_index.data(Qt::ToolTipRole).toString()};
        QVERIFY(tooltip.contains(record.label));
        QVERIFY(tooltip.contains(record.tooltip_text));
        QVERIFY(!tooltip.contains("Payment to yourself"));

        const QString plain_text{base.data(TransactionTableModel::TxPlainTextRole).toString()};
        QVERIFY(plain_text.contains(record.label));
        QVERIFY(!plain_text.contains("Payment to yourself"));

        const QString description{base.data(TransactionTableModel::LongDescriptionRole).toString()};
        QVERIFY(description.contains(record.label));
        QVERIFY(description.contains(QString::fromStdString(record.txid.ToString())));
        QVERIFY(description.contains("Net amount"));
        QVERIFY(description.contains("Transaction total size"));
        const QString summary{description.section("<hr>", 0, 0)};
        QVERIFY(!summary.contains("From:"));
        QVERIFY(!summary.contains("To:"));
        QVERIFY(!summary.contains("<b>Debit:</b>"));
        QVERIFY(!summary.contains("<b>Credit:</b>"));
        QVERIFY(!summary.contains("Output index"));
    }
}

} // namespace

void ProviderTransactionTests::transactionTypeSettingCompatibility_data()
{
    QTest::addColumn<int>("saved_index");
    QTest::addColumn<QString>("expected_text");
    QTest::addColumn<quint32>("expected_filter");

    QTest::newRow("data") << 12 << QString{"Data Transaction"}
                          << TransactionFilterProxy::TYPE(TransactionRecord::DataTransaction);
    QTest::newRow("dust") << 13 << QString{"Dust Receive"} << TransactionFilterProxy::TYPE(TransactionRecord::DustReceive);
    QTest::newRow("other") << 14 << QString{"Other"} << TransactionFilterProxy::TYPE(TransactionRecord::Other);
}

void ProviderTransactionTests::transactionTypeSettingCompatibility()
{
    QFETCH(int, saved_index);
    QFETCH(QString, expected_text);
    QFETCH(quint32, expected_filter);

    TransactionTypeSettingRestorer setting_restorer;
    QSettings{}.setValue("transactionType", saved_index);

    TransactionView transaction_view;
    QComboBox* const type_widget{FindTransactionTypeWidget(transaction_view)};
    QVERIFY(type_widget != nullptr);
    QCOMPARE(type_widget->currentIndex(), saved_index);
    QCOMPARE(type_widget->currentText(), expected_text);
    QCOMPARE(type_widget->currentData().toUInt(), expected_filter);
    QCOMPARE(type_widget->findText("Masternode"), 15);
}

void ProviderTransactionTests::providerTransactionHistory()
{
    TestChain100Setup test;
    m_node.setContext(&test.m_node);

    WalletContext& context{*m_node.walletLoader().context()};
    std::shared_ptr<CWallet> wallet{std::make_shared<CWallet>(test.m_node.chain.get(), test.m_node.coinjoin_loader.get(),
                                                              "", test.m_args, CreateMockWalletDatabase())};
    wallet->LoadWallet();
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(wallet->cs_wallet);
        wallet->SetupDescriptorScriptPubKeyMans("", "");

        FlatSigningProvider provider;
        std::string descriptor_error;
        std::unique_ptr<Descriptor> descriptor{Parse("combo(" + EncodeSecret(test.coinbaseKey) + ")", provider,
                                                     descriptor_error, /*require_checksum=*/false)};
        QVERIFY(descriptor != nullptr);
        WalletDescriptor wallet_descriptor{std::move(descriptor), 0, 0, 1, 1};
        QVERIFY(wallet->AddWalletDescriptor(wallet_descriptor, provider, "", /*internal=*/false));

        const CBlockIndex* const tip{
            WITH_LOCK(Assert(test.m_node.chainman)->GetMutex(), return test.m_node.chainman->ActiveChain().Tip())};
        wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
    }
    {
        WalletRescanReserver reserver{*wallet};
        QVERIFY(reserver.reserve());
        const CWallet::ScanResult result{wallet->ScanForWalletTransactions(Params().GetConsensus().hashGenesisBlock,
                                                                           /*start_height=*/0, /*max_height=*/{}, reserver,
                                                                           /*fUpdate=*/false, /*save_progress=*/false)};
        QCOMPARE(result.status, CWallet::ScanResult::SUCCESS);
        QVERIFY(result.last_failed_block.IsNull());
    }
    QVERIFY(AddWallet(context, wallet));
    WalletCleanup wallet_cleanup{context, wallet};
    TransactionTypeSettingRestorer setting_restorer;

    const CScript own_script{GetScriptForRawPubKey(test.coinbaseKey.GetPubKey())};
    CKey external_key;
    external_key.MakeNewKey(/*fCompressed=*/true);
    const CScript external_script{GetScriptForDestination(PKHash(external_key.GetPubKey()))};

    auto make_owned_input = [&test](size_t index) { return COutPoint{test.m_coinbase_txns.at(index)->GetHash(), 0}; };
    auto input_amount = [&test](size_t index) { return test.m_coinbase_txns.at(index)->vout.at(0).nValue; };

    const CAmount registration_fee{1000};
    const CAmount service_fee{2000};
    const CAmount registrar_fee{3000};
    const CAmount revoke_fee{4000};

    const CTransactionRef registration{MakeSpecialTransaction(TRANSACTION_PROVIDER_REGISTER, make_owned_input(0),
                                                              input_amount(0) - registration_fee, own_script)};
    const CTransactionRef update_service{MakeSpecialTransaction(TRANSACTION_PROVIDER_UPDATE_SERVICE, make_owned_input(1),
                                                                input_amount(1) - service_fee, own_script)};
    const CTransactionRef update_registrar{MakeSpecialTransaction(TRANSACTION_PROVIDER_UPDATE_REGISTRAR,
                                                                  make_owned_input(2), input_amount(2) - registrar_fee,
                                                                  external_script)};
    const CTransactionRef update_revoke{MakeSpecialTransaction(TRANSACTION_PROVIDER_UPDATE_REVOKE, make_owned_input(3),
                                                               input_amount(3) - revoke_fee, own_script)};
    const CTransactionRef other_special_tx{
        MakeSpecialTransaction(TRANSACTION_ASSET_LOCK, make_owned_input(4), input_amount(4) - 5000, own_script)};

    std::vector<ExpectedRecord> expected{
        {registration->GetHash(), TransactionRecord::MasternodeRegistration, -registration_fee,
         QString{"Masternode Registration"}, QString{"Registers a masternode"}},
        {update_service->GetHash(), TransactionRecord::MasternodeUpdate, -service_fee, QString{"Masternode Update"},
         QString{"Updates an existing masternode"}},
        // A provider transaction with an external output reports the complete wallet delta, not
        // just the fee or an arbitrary output amount.
        {update_registrar->GetHash(), TransactionRecord::MasternodeUpdate, -input_amount(2),
         QString{"Masternode Update"}, QString{"Updates an existing masternode"}},
        {update_revoke->GetHash(), TransactionRecord::MasternodeUpdate, -revoke_fee, QString{"Masternode Update"},
         QString{"Updates an existing masternode"}},
    };

    for (const CTransactionRef& tx : {registration, update_service, update_registrar, update_revoke, other_special_tx}) {
        QVERIFY(wallet->AddToWallet(tx, TxStateInactive{}) != nullptr);
    }

    OptionsModel options_model{m_node};
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model{m_node, &options_model};

    {
        WalletModel wallet_model{interfaces::MakeWallet(context, wallet), client_model};
        TransactionTableModel* const model{wallet_model.getTransactionTableModel()};

        // Transactions loaded before the model is constructed exercise the wallet-restart path.
        CheckProviderRecords(*model, expected);
        const std::vector<int> registrar_rows{FindTransactionRows(*model, update_registrar->GetHash())};
        QCOMPARE(registrar_rows.size(), size_t{1});
        const QString registrar_description{
            model->index(registrar_rows.front(), 0).data(TransactionTableModel::LongDescriptionRole).toString()};
        const QString registrar_summary{registrar_description.section("<hr>", 0, 0)};
        const QString external_address{QString::fromStdString(EncodeDestination(PKHash(external_key.GetPubKey())))};
        QVERIFY(!registrar_summary.contains(external_address));

        const std::vector<int> other_rows{FindTransactionRows(*model, other_special_tx->GetHash())};
        QCOMPARE(other_rows.size(), size_t{1});
        QCOMPARE(model->index(other_rows.front(), 0).data(TransactionTableModel::TypeRole).toInt(),
                 static_cast<int>(TransactionRecord::SendToSelf));
        QCOMPARE(model->index(other_rows.front(), TransactionTableModel::Type).data(Qt::DisplayRole).toString(),
                 QString{"Payment to yourself"});

        // Add an externally funded registration after model construction to exercise live wallet
        // notification. Its owned output is the wallet's positive net change and still yields one
        // logical registration record rather than one record per output.
        const CAmount received_collateral{1000 * COIN};
        const CTransactionRef received_registration{MakeSpecialTransaction(TRANSACTION_PROVIDER_REGISTER,
                                                                           COutPoint{uint256::ONE, 7},
                                                                           received_collateral, own_script)};
        QVERIFY(wallet->AddToWallet(received_registration, TxStateInactive{}) != nullptr);
        QTRY_COMPARE_WITH_TIMEOUT(FindTransactionRows(*model, received_registration->GetHash()).size(), size_t{1}, 5000);
        expected.push_back({received_registration->GetHash(), TransactionRecord::MasternodeRegistration,
                            received_collateral, QString{"Masternode Registration"}, QString{"Registers a masternode"}});
        CheckProviderRecords(*model, expected);

        const quint32 masternode_filter{TransactionFilterProxy::TYPE(TransactionRecord::MasternodeRegistration) |
                                        TransactionFilterProxy::TYPE(TransactionRecord::MasternodeUpdate)};
        TransactionFilterProxy filter;
        filter.setSourceModel(model);
        filter.setTypeFilter(masternode_filter);
        QCOMPARE(filter.rowCount(), static_cast<int>(expected.size()));

#if defined(Q_OS_MACOS)
        if (QApplication::platformName() == "minimal") {
            QWARN("Skipping TransactionView checks on macOS with the minimal platform due to QTBUG-49686");
        } else
#endif
        {
            CoinJoinOptionsRestorer coinjoin_restorer{m_node.coinJoinOptions()};
            m_node.coinJoinOptions().setEnabled(false);

            TransactionView transaction_view;
            transaction_view.setModel(&wallet_model);

            QComboBox* const type_widget{FindTransactionTypeWidget(transaction_view)};
            QVERIFY(type_widget != nullptr);
            const int masternode_row{type_widget->findText("Masternode")};
            QCOMPARE(type_widget->itemData(masternode_row).toUInt(), masternode_filter);

            QListView* const type_list{qobject_cast<QListView*>(type_widget->view())};
            QVERIFY(type_list != nullptr);
            for (const quint32 coinjoin_filter :
                 {TransactionFilterProxy::TYPE(TransactionRecord::CoinJoinSend),
                  TransactionFilterProxy::TYPE(TransactionRecord::CoinJoinMakeCollaterals),
                  TransactionFilterProxy::TYPE(TransactionRecord::CoinJoinCreateDenominations),
                  TransactionFilterProxy::TYPE(TransactionRecord::CoinJoinMixing),
                  TransactionFilterProxy::TYPE(TransactionRecord::CoinJoinCollateralPayment)}) {
                const int row{type_widget->findData(coinjoin_filter)};
                QVERIFY(row >= 0);
                QVERIFY(type_list->isRowHidden(row));
            }
            QVERIFY(!type_list->isRowHidden(masternode_row));

            type_widget->setCurrentIndex(masternode_row);
            transaction_view.chooseType(masternode_row);
            QTableView* const table{transaction_view.findChild<QTableView*>("transactionView")};
            QVERIFY(table != nullptr);
            QCOMPARE(table->model()->rowCount(), static_cast<int>(expected.size()));
        }
    }

    // Reconstructing the model must neither lose the classifications nor duplicate their rows.
    {
        WalletModel restarted_wallet_model{interfaces::MakeWallet(context, wallet), client_model};
        CheckProviderRecords(*restarted_wallet_model.getTransactionTableModel(), expected);
    }
}
