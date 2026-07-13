#!/usr/bin/env python3
# Copyright (c) 2022-2025 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import (
    DashTestFramework,
    MasternodeInfo,
)
from test_framework.util import assert_equal

'''
rpc_quorum.py

Test "quorum" rpc subcommands
'''

class RPCMasternodeTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        # A single-member quorum exercises the same per-member `quorum info`
        # output the test asserts, so one masternode is sufficient.
        self.set_dash_test_params(2, 1)
        self.set_dash_llmq_test_params(1, 1)

    def run_test(self):
        self.nodes[0].sporkupdate("SPORK_17_QUORUM_DKG_ENABLED", 0)
        self.wait_for_sporks_same()
        self.mine_until_mns_confirmed_for_next_dkg()
        quorum_hash = self.mine_quorum_single_member()

        quorum_info = self.nodes[0].quorum("info", 100, quorum_hash)
        for idx in range(0, self.mn_count):
            mn: MasternodeInfo = self.mninfo[idx]
            for member in quorum_info["members"]:
                if member["proTxHash"] == mn.proTxHash:
                    assert_equal(member['addresses']['core_p2p'][0], f'127.0.0.1:{mn.nodePort}')

if __name__ == '__main__':
    RPCMasternodeTest().main()
