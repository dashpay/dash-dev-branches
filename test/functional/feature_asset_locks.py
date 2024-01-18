#!/usr/bin/env python3

# Copyright (c) 2022 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import copy
import struct
from decimal import Decimal
from io import BytesIO

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.authproxy import JSONRPCException
from test_framework.key import ECKey
from test_framework.messages import (
    CAssetLockTx,
    CAssetUnlockTx,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    hash256,
    ser_string,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_RETURN,
    hash160,
)
from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    get_bip9_details,
    hex_str_to_bytes,
)

llmq_type_test = 106 # LLMQType::LLMQ_TEST_PLATFORM
tiny_amount = int(Decimal("0.0007") * COIN)
blocks_in_one_day = 576

class AssetLocksTest(DashTestFramework):
    def set_test_params(self):
        self.set_dash_test_params(5, 3, [["-whitelist=127.0.0.1", "-llmqtestinstantsenddip0024=llmq_test_instantsend"]] * 5, evo_count=3)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_assetlock(self, coin, amount, pubkey):
        node_wallet = self.nodes[0]


        inputs = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]

        credit_outputs = []
        tmp_amount = amount
        if tmp_amount > COIN:
            tmp_amount -= COIN
            credit_outputs.append(CTxOut(COIN, CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])))
        credit_outputs.append(CTxOut(tmp_amount, CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])))

        lockTx_payload = CAssetLockTx(1, credit_outputs)

        remaining = int(COIN * coin['amount']) - tiny_amount - amount

        tx_output_ret = CTxOut(amount, CScript([OP_RETURN, b""]))
        tx_output = CTxOut(remaining, CScript([pubkey, OP_CHECKSIG]))

        lock_tx = CTransaction()
        lock_tx.vin = inputs
        lock_tx.vout = [tx_output, tx_output_ret] if remaining > 0 else [tx_output_ret]
        lock_tx.nVersion = 3
        lock_tx.nType = 8 # asset lock type
        lock_tx.vExtraPayload = lockTx_payload.serialize()

        lock_tx = node_wallet.signrawtransactionwithwallet(lock_tx.serialize().hex())
        return FromHex(CTransaction(), lock_tx["hex"])


    def create_assetunlock(self, index, withdrawal, pubkey=None, fee=tiny_amount):
        node_wallet = self.nodes[0]
        mninfo = self.mninfo
        assert_greater_than(int(withdrawal), fee)
        tx_output = CTxOut(int(withdrawal) - fee, CScript([pubkey, OP_CHECKSIG]))

        # request ID = sha256("plwdtx", index)
        request_id_buf = ser_string(b"plwdtx") + struct.pack("<Q", index)
        request_id = hash256(request_id_buf)[::-1].hex()

        height = node_wallet.getblockcount()
        self.log.info(f"Creating asset unlock: {llmq_type_test} {request_id}")
        quorumHash = mninfo[0].node.quorum("selectquorum", llmq_type_test, request_id)["quorumHash"]
        self.log.info(f"Used quorum hash: {quorumHash}")
        unlockTx_payload = CAssetUnlockTx(
            version = 1,
            index = index,
            fee = fee,
            requestedHeight = height,
            quorumHash = int(quorumHash, 16),
            quorumSig = b'\00' * 96)

        unlock_tx = CTransaction()
        unlock_tx.vin = []
        unlock_tx.vout = [tx_output]
        unlock_tx.nVersion = 3
        unlock_tx.nType = 9 # asset unlock type
        unlock_tx.vExtraPayload = unlockTx_payload.serialize()

        unlock_tx.calc_sha256()
        msgHash = format(unlock_tx.sha256, '064x')

        recsig = self.get_recovered_sig(request_id, msgHash, llmq_type=llmq_type_test)

        unlockTx_payload.quorumSig = bytearray.fromhex(recsig["sig"])
        unlock_tx.vExtraPayload = unlockTx_payload.serialize()
        return unlock_tx

    def get_credit_pool_balance(self, node = None, block_hash = None):
        if node is None:
            node = self.nodes[0]

        if block_hash is None:
            block_hash = node.getbestblockhash()
        block = node.getblock(block_hash)
        return int(COIN * block['cbTx']['creditPoolBalance'])

    def validate_credit_pool_balance(self, expected = None, block_hash = None):
        for node in self.nodes:
            locked = self.get_credit_pool_balance(node=node, block_hash=block_hash)
            if expected is None:
                expected = locked
            else:
                assert_equal(expected, locked)
        self.log.info(f"Credit pool amount matched with '{expected}'")
        return expected

    def check_mempool_size(self):
        self.sync_mempools()
        for node in self.nodes:
            assert_equal(node.getmempoolinfo()['size'], self.mempool_size)

    def check_mempool_result(self, result_expected, tx):
        """Wrapper to check result of testmempoolaccept on node_0's mempool"""
        result_expected['txid'] = tx.rehash()

        result_test = self.nodes[0].testmempoolaccept([tx.serialize().hex()])

        assert_equal([result_expected], result_test)
        self.check_mempool_size()

    def create_and_check_block(self, txes, expected_error = None):
        node_wallet = self.nodes[0]
        best_block_hash = node_wallet.getbestblockhash()
        best_block = node_wallet.getblock(best_block_hash)
        tip = int(best_block_hash, 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        cbb = create_coinbase(height, dip4_activated=True, v20_activated=True)
        gbt = node_wallet.getblocktemplate()
        cbb.vExtraPayload = hex_str_to_bytes(gbt["coinbase_payload"])
        cbb.rehash()
        block = create_block(tip, cbb, block_time, version=4)
        # Add quorum commitments from block template
        for tx_obj in gbt["transactions"]:
            tx = FromHex(CTransaction(), tx_obj["data"])
            if tx.nType == 6:
                block.vtx.append(tx)
        for tx in txes:
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        result = node_wallet.submitblock(block.serialize().hex())
        if result != expected_error:
            raise AssertionError('mining the block should have failed with error %s, but submitblock returned %s' % (expected_error, result))

    def set_sporks(self):
        spork_enabled = 0
        spork_disabled = 4070908800

        self.nodes[0].sporkupdate("SPORK_17_QUORUM_DKG_ENABLED", spork_enabled)
        self.nodes[0].sporkupdate("SPORK_19_CHAINLOCKS_ENABLED", spork_disabled)
        self.nodes[0].sporkupdate("SPORK_3_INSTANTSEND_BLOCK_FILTERING", spork_disabled)
        self.nodes[0].sporkupdate("SPORK_2_INSTANTSEND_ENABLED", spork_disabled)
        self.wait_for_sporks_same()

    def ensure_tx_is_not_mined(self, tx_id):
        try:
            for node in self.nodes:
                node.gettransaction(tx_id)
            raise AssertionError("Transaction should not be mined")
        except JSONRPCException as e:
            assert "Invalid or non-wallet transaction id" in e.error['message']

    def send_tx_simple(self, tx):
        return self.nodes[0].sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)

    def send_tx(self, tx, expected_error = None, reason = None):
        try:
            self.log.info(f"Send tx with expected_error:'{expected_error}'...")
            tx_res = self.send_tx_simple(tx)
            if expected_error is None:
                self.sync_mempools()
                return tx_res

            # failure didn't happen, but expected:
            message = "Transaction should not be accepted"
            if reason is not None:
                message += ": " + reason

            raise AssertionError(message)
        except JSONRPCException as e:
            assert expected_error in e.error['message']

    def slowly_generate_batch(self, amount):
        self.log.info(f"Slowly generate {amount} blocks")
        while amount > 0:
            self.log.info(f"Generating batch of blocks {amount} left")
            next = min(10, amount)
            amount -= next
            self.bump_mocktime(next)
            self.nodes[1].generate(next)
            self.sync_all()

    def run_test(self):
        node_wallet = self.nodes[0]
        node = self.nodes[1]

        self.set_sporks()

        self.activate_v19(expected_activation_height=900)
        self.log.info("Activated v19 at height:" + str(node.getblockcount()))

        self.nodes[0].sporkupdate("SPORK_2_INSTANTSEND_ENABLED", 0)
        self.wait_for_sporks_same()

        self.mine_quorum(llmq_type_name='llmq_test_instantsend', llmq_type=104)

        for i in range(3):
            self.dynamically_add_masternode(evo=True)
            node.generate(8)
            self.sync_blocks()

        self.set_sporks()
        self.activate_v20()
        node.generate(1)
        self.sync_all()
        self.mempool_size = 0

        key = ECKey()
        key.generate()
        pubkey = key.get_pubkey().get_bytes()

        self.log.info("Testing asset lock...")
        locked_1 = 10 * COIN + 141421
        locked_2 = 10 * COIN + 314159

        coins = node_wallet.listunspent()
        coin = None
        while coin is None or COIN * coin['amount'] < locked_2:
            coin = coins.pop()
        asset_lock_tx = self.create_assetlock(coin, locked_1, pubkey)


        self.check_mempool_result(tx=asset_lock_tx, result_expected={'allowed': True})
        self.validate_credit_pool_balance(0)
        txid_in_block = self.send_tx(asset_lock_tx)
        assert "assetLockTx" in node.getrawtransaction(txid_in_block, 1)
        self.validate_credit_pool_balance(0)
        node.generate(1)
        assert_equal(self.get_credit_pool_balance(node=node), locked_1)
        self.log.info("Generate a number of blocks to ensure this is the longest chain for later in the test when we reconsiderblock")
        node.generate(12)
        self.sync_all()

        self.validate_credit_pool_balance(locked_1)

        # tx is mined, let's get blockhash
        self.log.info("Invalidate block with asset lock tx...")
        block_hash_1 = node_wallet.gettransaction(txid_in_block)['blockhash']
        for inode in self.nodes:
            inode.invalidateblock(block_hash_1)
            assert_equal(self.get_credit_pool_balance(node=inode), 0)
        node.generate(3)
        self.sync_all()
        self.validate_credit_pool_balance(0)
        self.log.info("Resubmit asset lock tx to new chain...")
        # NEW tx appears
        asset_lock_tx_2 = self.create_assetlock(coin, locked_2, pubkey)
        txid_in_block = self.send_tx(asset_lock_tx_2)
        node.generate(1)
        self.sync_all()
        self.validate_credit_pool_balance(locked_2)
        self.log.info("Reconsider old blocks...")
        for inode in self.nodes:
            inode.reconsiderblock(block_hash_1)
        self.validate_credit_pool_balance(locked_1)
        self.sync_all()

        self.log.info('Mine block with incorrect credit-pool value...')
        coin = coins.pop()
        extra_lock_tx = self.create_assetlock(coin, COIN, pubkey)
        self.create_and_check_block([extra_lock_tx], expected_error = 'bad-cbtx-assetlocked-amount')

        self.log.info("Mine a quorum...")
        self.mine_quorum(llmq_type_name='llmq_test_platform', llmq_type=106, expected_connections=2, expected_members=3, expected_contributions=3, expected_complaints=0, expected_justifications=0, expected_commitments=3 )

        self.validate_credit_pool_balance(locked_1)

        self.log.info("Testing asset unlock...")

        self.log.info("Generating several txes by same quorum....")
        self.validate_credit_pool_balance(locked_1)
        asset_unlock_tx = self.create_assetunlock(101, COIN, pubkey)
        asset_unlock_tx_late = self.create_assetunlock(102, COIN, pubkey)
        asset_unlock_tx_too_late = self.create_assetunlock(103, COIN, pubkey)
        asset_unlock_tx_too_big_fee = self.create_assetunlock(104, COIN, pubkey, fee=int(Decimal("0.1") * COIN))
        asset_unlock_tx_zero_fee = self.create_assetunlock(105, COIN, pubkey, fee=0)
        asset_unlock_tx_duplicate_index = copy.deepcopy(asset_unlock_tx)
        # modify this tx with duplicated index to make a hash of tx different, otherwise tx would be refused too early
        asset_unlock_tx_duplicate_index.vout[0].nValue += COIN
        too_late_height = node.getblockcount() + 48

        self.check_mempool_result(tx=asset_unlock_tx, result_expected={'allowed': True})
        self.check_mempool_result(tx=asset_unlock_tx_too_big_fee,
                result_expected={'allowed': False, 'reject-reason' : 'absurdly-high-fee'})
        self.check_mempool_result(tx=asset_unlock_tx_zero_fee,
                result_expected={'allowed': False, 'reject-reason' : 'bad-txns-assetunlock-fee-outofrange'})
        # not-verified is a correct faiure from mempool. Mempool knows nothing about CreditPool indexes and he just report that signature is not validated
        self.check_mempool_result(tx=asset_unlock_tx_duplicate_index,
                result_expected={'allowed': False, 'reject-reason' : 'bad-assetunlock-not-verified'})

        self.log.info("Validating that we calculate payload hash correctly: ask quorum forcely by message hash...")
        asset_unlock_tx_payload = CAssetUnlockTx()
        asset_unlock_tx_payload.deserialize(BytesIO(asset_unlock_tx.vExtraPayload))

        assert_equal(asset_unlock_tx_payload.quorumHash, int(self.mninfo[0].node.quorum("selectquorum", llmq_type_test, 'e6c7a809d79f78ea85b72d5df7e9bd592aecf151e679d6e976b74f053a7f9056')["quorumHash"], 16))

        txid = self.send_tx(asset_unlock_tx)
        assert "assetUnlockTx" in node.getrawtransaction(txid, 1)

        indexes_statuses = self.nodes[0].getassetunlockstatuses(["101", "102", "300"])
        assert_equal([{'index': 101, 'status': 'mempooled'}, {'index': 102, 'status': 'unknown'}, {'index': 300, 'status': 'unknown'}], indexes_statuses)

        self.mempool_size += 1
        self.check_mempool_size()
        self.validate_credit_pool_balance(locked_1)
        node.generate(1)
        self.sync_all()
        self.validate_credit_pool_balance(locked_1 - COIN)
        self.mempool_size -= 1
        self.check_mempool_size()
        block_asset_unlock = node.getrawtransaction(asset_unlock_tx.rehash(), 1)['blockhash']

        self.send_tx(asset_unlock_tx,
            expected_error = "Transaction already in block chain",
            reason = "double copy")

        self.log.info("Mining next quorum to check tx 'asset_unlock_tx_late' is still valid...")
        self.mine_quorum(llmq_type_name="llmq_test_platform", llmq_type=106)
        self.log.info("Checking credit pool amount is same...")
        self.validate_credit_pool_balance(locked_1 - 1 * COIN)
        self.check_mempool_result(tx=asset_unlock_tx_late, result_expected={'allowed': True})
        self.log.info("Checking credit pool amount still is same...")
        self.validate_credit_pool_balance(locked_1 - 1 * COIN)
        self.send_tx(asset_unlock_tx_late)
        node.generate(1)
        self.sync_all()
        self.validate_credit_pool_balance(locked_1 - 2 * COIN)

        self.log.info("Generating many blocks to make quorum far behind (even still active)...")
        self.slowly_generate_batch(too_late_height - node.getblockcount() - 1)
        self.check_mempool_result(tx=asset_unlock_tx_too_late, result_expected={'allowed': True})
        node.generate(1)
        self.sync_all()
        self.check_mempool_result(tx=asset_unlock_tx_too_late,
                result_expected={'allowed': False, 'reject-reason' : 'bad-assetunlock-too-late'})

        self.log.info("Checking that two quorums later it is too late because quorum is not active...")
        self.mine_quorum(llmq_type_name="llmq_test_platform", llmq_type=106)
        self.log.info("Expecting new reject-reason...")
        self.check_mempool_result(tx=asset_unlock_tx_too_late,
                result_expected={'allowed': False, 'reject-reason' : 'bad-assetunlock-not-active-quorum'})

        block_to_reconsider = node.getbestblockhash()
        self.log.info("Test block invalidation with asset unlock tx...")
        for inode in self.nodes:
            inode.invalidateblock(block_asset_unlock)
        self.validate_credit_pool_balance(locked_1)
        self.slowly_generate_batch(50)
        self.validate_credit_pool_balance(locked_1)
        for inode in self.nodes:
            inode.reconsiderblock(block_to_reconsider)
        self.validate_credit_pool_balance(locked_1 - 2 * COIN)

        self.log.info("Forcibly mining asset_unlock_tx_too_late and ensure block is invalid...")
        self.create_and_check_block([asset_unlock_tx_too_late], expected_error = "bad-assetunlock-not-active-quorum")

        node.generate(1)
        self.sync_all()

        self.validate_credit_pool_balance(locked_1 - 2 * COIN)
        self.validate_credit_pool_balance(block_hash=block_hash_1, expected=locked_1)

        self.log.info("Checking too big withdrawal... expected to not be mined")
        asset_unlock_tx_full = self.create_assetunlock(201, 1 + self.get_credit_pool_balance(), pubkey)

        self.log.info("Checking that transaction with exceeding amount accepted by mempool...")
        # Mempool doesn't know about the size of the credit pool
        self.check_mempool_result(tx=asset_unlock_tx_full, result_expected={'allowed': True })

        txid_in_block = self.send_tx(asset_unlock_tx_full)
        node.generate(1)
        self.sync_all()

        self.ensure_tx_is_not_mined(txid_in_block)

        self.log.info("Forcibly mine asset_unlock_tx_full and ensure block is invalid...")
        self.create_and_check_block([asset_unlock_tx_full], expected_error = "failed-creditpool-unlock-too-much")

        self.mempool_size += 1
        asset_unlock_tx_full = self.create_assetunlock(301, self.get_credit_pool_balance(), pubkey)
        self.check_mempool_result(tx=asset_unlock_tx_full, result_expected={'allowed': True })

        txid_in_block = self.send_tx(asset_unlock_tx_full)
        node.generate(1)
        self.sync_all()
        self.log.info("Check txid_in_block was mined...")
        block = node.getblock(node.getbestblockhash())
        assert txid_in_block in block['tx']
        self.validate_credit_pool_balance(0)

        self.log.info("Forcibly mine asset_unlock_tx_full and ensure block is invalid...")
        self.create_and_check_block([asset_unlock_tx_duplicate_index], expected_error = "bad-assetunlock-duplicated-index")

        self.log.info("Fast forward to the next day to reset all current unlock limits...")
        self.slowly_generate_batch(blocks_in_one_day  + 1)
        self.mine_quorum(llmq_type_name="llmq_test_platform", llmq_type=106)

        total = self.get_credit_pool_balance()
        while total <= 10_900 * COIN:
            self.log.info(f"Collecting coins in pool... Collected {total}/{10_900 * COIN}")
            coin = coins.pop()
            to_lock = int(coin['amount'] * COIN) - tiny_amount
            if to_lock > 99 * COIN:
                to_lock = 99 * COIN
            total += to_lock
            tx = self.create_assetlock(coin, to_lock, pubkey)
            self.send_tx_simple(tx)
        self.sync_mempools()
        node.generate(1)
        self.sync_all()
        credit_pool_balance_1 = self.get_credit_pool_balance()
        assert_greater_than(credit_pool_balance_1, 10_900 * COIN)
        limit_amount_1 = 1000 * COIN
        # take most of limit by one big tx for faster testing and
        # create several tiny withdrawal with exactly 1 *invalid* / causes spend above limit tx
        withdrawals = [600 * COIN, 131 * COIN, 131 * COIN, 131 * COIN, 131 * COIN]
        amount_to_withdraw_1 = sum(withdrawals)
        index = 400
        for next_amount in withdrawals:
            index += 1
            asset_unlock_tx = self.create_assetunlock(index, next_amount, pubkey)
            self.send_tx_simple(asset_unlock_tx)
            if index == 401:
                self.sync_mempools()
                node.generate(1)

        self.sync_mempools()
        node.generate(1)
        self.sync_all()
        self.log.info(f"MN_RR status: {get_bip9_details(node, 'mn_rr')}")

        new_total = self.get_credit_pool_balance()
        amount_actually_withdrawn = total - new_total
        block = node.getblock(node.getbestblockhash())
        self.log.info("Testing that we tried to withdraw more than we could...")
        assert_greater_than(amount_to_withdraw_1, amount_actually_withdrawn)
        self.log.info("Checking that we tried to withdraw more than the limit...")
        assert_greater_than(amount_to_withdraw_1, limit_amount_1)
        self.log.info("Checking we didn't actually withdraw more than allowed by the limit...")
        assert_greater_than_or_equal(limit_amount_1, amount_actually_withdrawn)
        assert_equal(amount_actually_withdrawn, 993 * COIN)
        node.generate(1)
        self.sync_all()
        self.log.info("Checking that exactly 1 tx stayed in mempool...")
        self.mempool_size = 1
        self.check_mempool_size()

        assert_equal(new_total, self.get_credit_pool_balance())
        self.log.info("Fast forward to next day again...")
        self.slowly_generate_batch(blocks_in_one_day - 2)
        self.log.info("Checking mempool is empty now...")
        self.mempool_size = 0
        self.check_mempool_size()

        self.log.info("Creating new asset-unlock tx. It should be mined exactly 1 block after")
        credit_pool_balance_2 = self.get_credit_pool_balance()
        limit_amount_2 = credit_pool_balance_2 // 10
        index += 1
        asset_unlock_tx = self.create_assetunlock(index, limit_amount_2, pubkey)
        self.send_tx(asset_unlock_tx)
        node.generate(1)
        self.sync_all()
        assert_equal(new_total, self.get_credit_pool_balance())
        node.generate(1)
        self.sync_all()
        new_total -= limit_amount_2
        assert_equal(new_total, self.get_credit_pool_balance())
        self.log.info("Trying to withdraw more... expecting to fail")
        index += 1
        asset_unlock_tx = self.create_assetunlock(index, COIN * 100, pubkey)
        self.send_tx(asset_unlock_tx)
        node.generate(1)
        self.sync_all()

        indexes_statuses = self.nodes[0].getassetunlockstatuses(["101", "102", "103"])
        assert_equal([{'index': 101, 'status': 'mined'}, {'index': 102, 'status': 'mined'}, {'index': 103, 'status': 'unknown'}], indexes_statuses)

        self.log.info("generate many blocks to be sure that mempool is empty after expiring txes...")
        self.slowly_generate_batch(60)
        self.log.info("Checking that credit pool is not changed...")
        assert_equal(new_total, self.get_credit_pool_balance())
        self.check_mempool_size()

        # activate MN_RR reallocation
        self.log.info("Activate mn_rr...")
        self.activate_mn_rr(expected_activation_height=node.getblockcount() + 12 * 3)
        self.log.info(f'height: {node.getblockcount()} credit: {self.get_credit_pool_balance()}')
        assert_equal(new_total, self.get_credit_pool_balance())

        bt = node.getblocktemplate()
        platform_reward = bt['masternode'][0]['amount']
        assert_equal(bt['masternode'][0]['script'], '6a')  # empty OP_RETURN
        owner_reward = bt['masternode'][1]['amount']
        operator_reward = bt['masternode'][2]['amount'] if len(bt['masternode']) == 3 else 0
        all_mn_rewards = platform_reward + owner_reward + operator_reward
        assert_equal(all_mn_rewards, bt['coinbasevalue'] * 3 // 4)  # 75/25 mn/miner reward split
        assert_equal(platform_reward, all_mn_rewards * 375 // 1000)  # 0.375 platform share
        assert_equal(platform_reward, 31916328)
        assert_equal(new_total, self.get_credit_pool_balance())
        node.generate(1)
        self.sync_all()
        new_total += platform_reward
        assert_equal(new_total, self.get_credit_pool_balance())

        coin = coins.pop()
        self.send_tx(self.create_assetlock(coin, COIN, pubkey))
        new_total += platform_reward + COIN
        node.generate(1)
        self.sync_all()
        assert_equal(new_total, self.get_credit_pool_balance())


if __name__ == '__main__':
    AssetLocksTest().main()
