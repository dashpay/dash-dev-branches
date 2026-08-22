// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_PROVIDERTX_H
#define BITCOIN_INTERFACES_PROVIDERTX_H

#include <bls/bls.h>
#include <evo/dmn_types.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/standard.h>
#include <uint256.h>
#include <util/translation.h>

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

enum class TransactionError;

namespace interfaces {

enum class ProviderTxErrorCode {
    INVALID_PARAMETER,
    INVALID_ADDRESS_OR_KEY,
    FUNDING_ERROR,
    WALLET_ERROR,
    WALLET_UNLOCK_NEEDED,
    INTERNAL_ERROR,
    VERIFY_ERROR,
    CONSENSUS_REJECTED,
    BROADCAST_ERROR,
};

struct ProviderTxError {
    ProviderTxErrorCode code{ProviderTxErrorCode::INTERNAL_ERROR};
    bilingual_str message;
    std::string reject_reason;
    std::optional<TransactionError> transaction_error;
};

template <typename T>
using ProviderTxResult = std::variant<T, ProviderTxError>;

struct ProviderTxSubmission {
    CTransactionRef tx;
    bool submitted{false};
};

struct PreparedProviderRegistration {
    CTransactionRef tx;
    CTxDestination collateral_address;
    std::string sign_message;
    //! True only if this prepare call newly locked the collateral. A successful prepare
    //! leaves the lock held; the caller may release this one lock if the flow is discarded.
    bool collateral_lock_acquired{false};
};

//! A point-in-time view of the provider transaction rules. Transaction creation and
//! submission always re-evaluate the active rules and can reject a stale request.
struct ProviderTxCapabilities {
    uint16_t version{0};
    bool extended_addresses{false};
};

using ProviderPlatformEndpoints = std::variant<std::monostate, uint16_t, std::vector<std::string>>;

struct ProviderNetInfo {
    std::vector<std::string> core_p2p;
    ProviderPlatformEndpoints platform_p2p;
    ProviderPlatformEndpoints platform_https;
};

struct ProviderPayout {
    static constexpr uint16_t MAX_REWARD{10000};

    CTxDestination destination;
    uint16_t reward{0};
};

struct FundProviderCollateral {
    CTxDestination destination;
};

struct ExistingProviderCollateral {
    COutPoint outpoint;
};

using ProviderCollateral = std::variant<FundProviderCollateral, ExistingProviderCollateral>;

struct ProviderRegistrationRequest {
    MnType type{MnType::Regular};
    ProviderCollateral collateral;
    ProviderNetInfo net_info;
    CKeyID owner_key;
    CBLSPublicKey operator_key;
    CKeyID voting_key;
    uint16_t operator_reward{0};
    std::vector<ProviderPayout> payouts;
    //! Whether payouts use the version-3 extended representation, even if there is only one.
    bool uses_extended_payouts{false};
    std::optional<uint160> platform_node_id;
    std::optional<CTxDestination> fee_source;
    bool use_legacy_bls_scheme{false};
    bool submit{true};
};

struct ProviderUpdateServiceRequest {
    MnType type{MnType::Regular};
    uint256 pro_tx_hash;
    ProviderNetInfo net_info;
    CBLSSecretKey operator_key;
    std::optional<uint160> platform_node_id;
    std::optional<CTxDestination> operator_payout;
    std::optional<CTxDestination> fee_source;
    bool submit{true};
};

struct ProviderUpdateRegistrarRequest {
    uint256 pro_tx_hash;
    std::optional<CBLSPublicKey> operator_key;
    std::optional<CKeyID> voting_key;
    std::optional<std::vector<ProviderPayout>> payouts;
    //! Whether payouts use the version-3 extended representation, even if there is only one.
    bool uses_extended_payouts{false};
    std::optional<CTxDestination> fee_source;
    bool use_legacy_bls_scheme{false};
    bool submit{true};
};

struct ProviderRevokeRequest {
    uint256 pro_tx_hash;
    CBLSSecretKey operator_key;
    uint16_t reason{0};
    std::optional<CTxDestination> fee_source;
    bool submit{true};
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_PROVIDERTX_H
