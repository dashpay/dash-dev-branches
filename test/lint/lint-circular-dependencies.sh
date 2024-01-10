#!/usr/bin/env bash
#
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

export LC_ALL=C

EXPECTED_CIRCULAR_DEPENDENCIES=(
    "chainparamsbase -> util/system -> chainparamsbase"
    "node/blockstorage -> validation -> node/blockstorage"
    "index/blockfilterindex -> node/blockstorage -> validation -> index/blockfilterindex"
    "index/base -> validation -> index/blockfilterindex -> index/base"
    "index/coinstatsindex -> node/coinstats -> index/coinstatsindex"
    "policy/fees -> txmempool -> policy/fees"
    "qt/addresstablemodel -> qt/walletmodel -> qt/addresstablemodel"
    "qt/bitcoingui -> qt/walletframe -> qt/bitcoingui"
    "qt/recentrequeststablemodel -> qt/walletmodel -> qt/recentrequeststablemodel"
    "qt/transactiontablemodel -> qt/walletmodel -> qt/transactiontablemodel"
    "txmempool -> validation -> txmempool"
    "wallet/fees -> wallet/wallet -> wallet/fees"
    "wallet/wallet -> wallet/walletdb -> wallet/wallet"
    "node/coinstats -> validation -> node/coinstats"
    # Dash
    "coinjoin/server -> core_io -> evo/assetlocktx -> llmq/signing -> net_processing -> coinjoin/server"
    "coinjoin/coinjoin -> llmq/instantsend -> net_processing -> coinjoin/server -> coinjoin/coinjoin"
    "dsnotificationinterface -> llmq/chainlocks -> node/blockstorage -> dsnotificationinterface"
    "evo/cbtx -> evo/simplifiedmns -> evo/cbtx"
    "evo/deterministicmns -> llmq/commitment -> evo/deterministicmns"
    "evo/deterministicmns -> llmq/utils -> evo/deterministicmns"
    "governance/classes -> governance/governance -> governance/classes"
    "governance/governance -> governance/object -> governance/governance"
    "governance/governance -> masternode/sync -> governance/governance"
    "llmq/quorums -> llmq/utils -> llmq/quorums"
    "llmq/chainlocks -> llmq/instantsend -> llmq/chainlocks"
    "llmq/chainlocks -> llmq/instantsend -> net_processing -> llmq/chainlocks"
    "llmq/dkgsessionmgr -> net_processing -> llmq/dkgsessionmgr"
    "llmq/instantsend -> net_processing -> llmq/instantsend"
    "llmq/instantsend -> txmempool -> llmq/instantsend"
    "llmq/instantsend -> validation -> llmq/instantsend"
    "llmq/signing -> llmq/signing_shares -> llmq/signing"
    "llmq/signing -> net_processing -> llmq/signing"
    "llmq/signing_shares -> net_processing -> llmq/signing_shares"
    "logging -> util/system -> logging"
    "masternode/payments -> validation -> masternode/payments"
    "masternode/sync -> validation -> masternode/sync"
    "net -> netmessagemaker -> net"
    "netaddress -> netbase -> netaddress"
    "qt/appearancewidget -> qt/guiutil -> qt/appearancewidget"
    "qt/bitcoinaddressvalidator -> qt/guiutil -> qt/bitcoinaddressvalidator"
    "qt/bitcoingui -> qt/guiutil -> qt/bitcoingui"
    "qt/guiutil -> qt/optionsdialog -> qt/guiutil"
    "qt/guiutil -> qt/qvalidatedlineedit -> qt/guiutil"
    "core_io -> evo/cbtx -> evo/simplifiedmns -> core_io"
    "core_io -> evo/assetlocktx -> llmq/signing -> net_processing -> governance/governance -> governance/object -> core_io"
    "llmq/dkgsession -> llmq/dkgsessionmgr -> llmq/dkgsessionhandler -> llmq/dkgsession"
    "logging -> util/system -> sync -> logging"
    "logging -> util/system -> stacktraces -> logging"
    "logging -> util/system -> util/getuniquepath -> random -> logging"
    "coinjoin/context -> coinjoin/server -> core_io -> evo/assetlocktx -> llmq/signing -> net_processing -> coinjoin/context"
    "qt/appearancewidget -> qt/guiutil -> qt/optionsdialog -> qt/appearancewidget"
    "qt/guiutil -> qt/optionsdialog -> qt/optionsmodel -> qt/guiutil"

    "bloom -> evo/assetlocktx -> llmq/quorums -> net -> bloom"
    "bloom -> evo/assetlocktx -> llmq/signing -> net_processing -> governance/governance -> bloom"
    "bloom -> evo/assetlocktx -> llmq/signing -> net_processing -> merkleblock -> bloom"
    "banman -> bloom -> evo/assetlocktx -> llmq/quorums -> net -> banman"
    "banman -> bloom -> evo/assetlocktx -> llmq/signing -> net_processing -> banman"

    "coinjoin/client -> coinjoin/coinjoin -> llmq/instantsend -> net_processing -> coinjoin/client"
    "coinjoin/client -> coinjoin/coinjoin -> llmq/instantsend -> net_processing -> coinjoin/context -> coinjoin/client"
    "llmq/dkgsession -> llmq/dkgsessionmgr -> llmq/dkgsession"
    "llmq/chainlocks -> validation -> llmq/chainlocks"
    "coinjoin/coinjoin -> llmq/chainlocks -> net -> coinjoin/coinjoin"
    "evo/deterministicmns -> llmq/utils -> llmq/snapshot -> evo/simplifiedmns -> evo/deterministicmns"
    "evo/deterministicmns -> llmq/utils -> net -> evo/deterministicmns"
    "policy/policy -> policy/settings -> policy/policy"
    "evo/specialtxman -> validation -> evo/specialtxman"
    "consensus/tx_verify -> evo/assetlocktx -> validation -> consensus/tx_verify"
    "consensus/tx_verify -> evo/assetlocktx -> llmq/signing -> net_processing -> txmempool -> consensus/tx_verify"
    "evo/assetlocktx -> llmq/signing -> net_processing -> txmempool -> evo/assetlocktx"

    "evo/simplifiedmns -> llmq/blockprocessor -> llmq/utils -> llmq/snapshot -> evo/simplifiedmns"
    "llmq/blockprocessor -> llmq/utils -> llmq/snapshot -> llmq/blockprocessor"
    "llmq/context -> llmq/dkgsessionmgr -> net_processing -> llmq/context"
    "llmq/dkgsession -> llmq/dkgsessionmgr -> llmq/quorums -> llmq/dkgsession"
    "llmq/dkgsessionmgr -> llmq/quorums -> llmq/dkgsessionmgr"
    "llmq/commitment -> llmq/utils -> llmq/snapshot -> llmq/commitment"
    "spork -> validation -> spork"
    "governance/governance -> validation -> governance/governance"
    "evo/deterministicmns -> validationinterface -> governance/vote -> evo/deterministicmns"
    "governance/vote -> validation -> validationinterface -> governance/vote"
    "llmq/signing -> masternode/node -> validationinterface -> llmq/signing"
    "evo/mnhftx -> validation -> evo/mnhftx"
    "evo/deterministicmns -> validation -> evo/deterministicmns"
)

EXIT_CODE=0

CIRCULAR_DEPENDENCIES=()

IFS=$'\n'
for CIRC in $(cd src && ../contrib/devtools/circular-dependencies.py {*,*/*,*/*/*}.{h,cpp} | sed -e 's/^Circular dependency: //'); do
    CIRCULAR_DEPENDENCIES+=( "$CIRC" )
    IS_EXPECTED_CIRC=0
    for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_EXPECTED_CIRC} == 0 ]]; then
        echo "A new circular dependency in the form of \"${CIRC}\" appears to have been introduced."
        echo
        EXIT_CODE=1
    fi
done

for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
    IS_PRESENT_EXPECTED_CIRC=0
    for CIRC in "${CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_PRESENT_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_PRESENT_EXPECTED_CIRC} == 0 ]]; then
        echo "Good job! The circular dependency \"${EXPECTED_CIRC}\" is no longer present."
        echo "Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in $0"
        echo "to make sure this circular dependency is not accidentally reintroduced."
        echo
        EXIT_CODE=1
    fi
done

exit ${EXIT_CODE}
