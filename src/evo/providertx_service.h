// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_PROVIDERTX_SERVICE_H
#define BITCOIN_EVO_PROVIDERTX_SERVICE_H

#include <interfaces/providertx.h>

#include <optional>

namespace interfaces {
class Wallet;
} // namespace interfaces

namespace node {
struct NodeContext;
} // namespace node

namespace evo::provider {

interfaces::ProviderTxCapabilities GetCapabilities(node::NodeContext& node,
                                                   std::optional<bool> basic_override = std::nullopt);

std::optional<interfaces::ProviderTxError> ValidateNetInfo(const interfaces::ProviderNetInfo& net_info, MnType type,
                                                           uint16_t version, bool optional);

interfaces::ProviderTxResult<interfaces::ProviderTxSubmission> Register(
    node::NodeContext& node, interfaces::Wallet& wallet, const interfaces::ProviderRegistrationRequest& request);

interfaces::ProviderTxResult<interfaces::PreparedProviderRegistration> PrepareRegistration(
    node::NodeContext& node, interfaces::Wallet& wallet, const interfaces::ProviderRegistrationRequest& request);

interfaces::ProviderTxResult<interfaces::ProviderTxSubmission> SubmitRegistration(
    node::NodeContext& node, interfaces::Wallet& wallet, const CTransactionRef& tx,
    const std::vector<unsigned char>& collateral_signature);

interfaces::ProviderTxResult<interfaces::ProviderTxSubmission> UpdateService(
    node::NodeContext& node, interfaces::Wallet& wallet, const interfaces::ProviderUpdateServiceRequest& request);

interfaces::ProviderTxResult<interfaces::ProviderTxSubmission> UpdateRegistrar(
    node::NodeContext& node, interfaces::Wallet& wallet, const interfaces::ProviderUpdateRegistrarRequest& request);

interfaces::ProviderTxResult<interfaces::ProviderTxSubmission> Revoke(node::NodeContext& node, interfaces::Wallet& wallet,
                                                                      const interfaces::ProviderRevokeRequest& request);

} // namespace evo::provider

#endif // BITCOIN_EVO_PROVIDERTX_SERVICE_H
