#!/usr/bin/env python3

# Copyright (c) 2022 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import copy
from decimal import Decimal
from io import BytesIO

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.authproxy import JSONRPCException
from test_framework.key import ECKey
from test_framework.messages import (
    FromHex,
    CAssetLockTx,
    CAssetUnlockTx,
    COutPoint,
    CTxOut,
    CTxIn,
    COIN,
    CTransaction,
)
from test_framework.script import (
    hash160,
    CScript,
    OP_HASH160,
    OP_RETURN,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
)
from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    wait_until,
)

llmq_type_test = 100
tiny_amount = int(Decimal("0.0007") * COIN)
blocks_in_one_day = 576

def create_assetlock(node, coin, amount, pubkey):
    inputs = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]

    credit_outputs = CTxOut(amount, CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG]))

    lockTx_payload = CAssetLockTx(1, 0, [credit_outputs])

    remaining = int(COIN * coin['amount']) - tiny_amount - credit_outputs.nValue

    tx_output_ret = CTxOut(credit_outputs.nValue, CScript([OP_RETURN, b""]))
    tx_output = CTxOut(remaining, CScript([pubkey, OP_CHECKSIG]))

    lock_tx = CTransaction()
    lock_tx.vin = inputs
    lock_tx.vout = [tx_output, tx_output_ret] if remaining > 0 else [tx_output_ret]
    lock_tx.nVersion = 3
    lock_tx.nType = 8 # asset lock type
    lock_tx.vExtraPayload = lockTx_payload.serialize()

    lock_tx = node.signrawtransactionwithwallet(lock_tx.serialize().hex())
    return FromHex(CTransaction(), lock_tx["hex"])


def create_assetunlock(node, mninfo, index, withdrawal, pubkey=None):
    def check_sigs(mninfo, id, msgHash):
        for mn in mninfo:
            if not mn.node.quorum("hasrecsig", llmq_type_test, id, msgHash):
                return False
        return True

    def wait_for_sigs(mninfo, id, msgHash, timeout):
        wait_until(lambda: check_sigs(mninfo, id, msgHash), timeout = timeout)

    tx_output = CTxOut(int(withdrawal) - tiny_amount, CScript([pubkey, OP_CHECKSIG]))

    # request ID = sha256("plwdtx", index)
    sha256 = hashlib.sha256()
    sha256.update(("plwdtx" + str(index)).encode())
    id = sha256.digest()[::-1].hex()

    height = node.getblockcount()
    quorumHash = mninfo[0].node.quorum("selectquorum", llmq_type_test, id)["quorumHash"]
    unlockTx_payload = CAssetUnlockTx(
        version = 1,
        index = index,
        fee = tiny_amount,
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

    for mn in mninfo:
        mn.node.quorum("sign", llmq_type_test, id, msgHash, quorumHash)

    wait_for_sigs(mninfo, id, msgHash, 5)

    recsig = mninfo[0].node.quorum("getrecsig", llmq_type_test, id, msgHash)

    unlockTx_payload.quorumSig = bytearray.fromhex(recsig["sig"])
    unlock_tx.vExtraPayload = unlockTx_payload.serialize()
    return unlock_tx

def get_credit_pool_amount(node, block_hash = None):
    if block_hash is None:
        block_hash = node.getbestblockhash()
    block = node.getblock(block_hash)
    return int(COIN * block['cbTx']['assetLockedAmount'])

class AssetLocksTest(DashTestFramework):
    def set_test_params(self):
        self.set_dash_test_params(4, 3)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def check_mempool_size(self):
        assert_equal(self.nodes[0].getmempoolinfo()['size'], self.mempool_size)  # Must not change mempool state

    def check_mempool_result(self, result_expected, tx):
        """Wrapper to check result of testmempoolaccept on node_0's mempool"""
        result_expected['txid'] = tx.rehash()

        result_test = self.nodes[0].testmempoolaccept([tx.serialize().hex()])

        assert_equal([result_expected], result_test)
        self.check_mempool_size()

    def set_sporks(self):
        spork_enabled = 0
        spork_disabled = 4070908800

        self.nodes[0].sporkupdate("SPORK_17_QUORUM_DKG_ENABLED", spork_enabled)
        self.nodes[0].sporkupdate("SPORK_19_CHAINLOCKS_ENABLED", spork_disabled)
        self.nodes[0].sporkupdate("SPORK_3_INSTANTSEND_BLOCK_FILTERING", spork_disabled)
        self.nodes[0].sporkupdate("SPORK_2_INSTANTSEND_ENABLED", spork_disabled)
        self.wait_for_sporks_same()

    def send_tx(self, tx, expected_error = None, reason = None):
        try:
            tx = self.nodes[0].sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)
            if expected_error is None:
                return tx

            # failure didn't happen, but expected:
            message = "Transaction should not be accepted"
            if reason is not None:
                message += ": " + reason

            raise AssertionError(message)
        except JSONRPCException as e:
            assert expected_error in e.error['message']

    def slowly_generate_batch(self, amount):
        while amount > 0:
            self.log.info(f"Generating batch of blocks {amount} left")
            next = min(10, amount)
            amount -= next
            self.bump_mocktime(next)
            self.nodes[0].generate(next)
            self.sync_all()

    def run_test(self):
        node = self.nodes[0]

        self.set_sporks()
        self.activate_v20()

        self.mempool_size = 0
        assert_equal(node.getmempoolinfo()['size'], self.mempool_size)

        key = ECKey()
        key.generate()
        pubkey = key.get_pubkey().get_bytes()

        self.log.info("Testing asset lock...")
        coins = node.listunspent()
        coin = coins.pop()
        locked_1 = 10 * COIN + 141421
        locked_2 = 10 * COIN + 314159
        while COIN * coin['amount'] < locked_2:
            coin = coins.pop()
        asset_lock_tx = create_assetlock(node, coin, locked_1, pubkey)

        self.check_mempool_result(tx=asset_lock_tx, result_expected={'allowed': True})
        assert_equal(get_credit_pool_amount(node), 0)
        txid_in_block = self.send_tx(asset_lock_tx)

        self.sync_mempools()
        assert_equal(get_credit_pool_amount(node), 0)

        node.generate(1)
        assert_equal(get_credit_pool_amount(node), locked_1)
        # Generate a number of blocks to ensure this is the longest chain for later in the test when we reconsiderblock
        node.generate(12)
        self.sync_all()

        assert_equal(get_credit_pool_amount(node), locked_1)
        assert_equal(get_credit_pool_amount(self.nodes[1]), locked_1)

        # tx is mined, let's get blockhash
        self.log.info("Invalidate block with asset lock tx...")
        block_hash_1 = node.gettransaction(txid_in_block)['blockhash']
        for inode in self.nodes:
            inode.invalidateblock(block_hash_1)
            assert_equal(get_credit_pool_amount(inode), 0)
        node.generate(3)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), 0)
        self.log.info("Resubmit asset lock tx to new chain...")
        # NEW tx appears
        asset_lock_tx_2 = create_assetlock(node, coin, locked_2, pubkey)
        txid_in_block = self.send_tx(asset_lock_tx_2)
        node.generate(1)
        self.sync_all()

        assert_equal(get_credit_pool_amount(node), locked_2)

        node.generate(3)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), locked_2)
        self.log.info("Reconsider old blocks...")
        for inode in self.nodes:
            inode.reconsiderblock(block_hash_1)
        assert_equal(get_credit_pool_amount(node), locked_1)
        self.sync_all()

        self.log.info("Mine a quorum...")
        self.mine_quorum()
        node.generate(3)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), locked_1)

        self.log.info("Testing asset unlock...")
        # These should all have been generated by the same quorum
        asset_unlock_tx = create_assetunlock(node, self.mninfo, 101, COIN, pubkey)
        asset_unlock_tx_late = create_assetunlock(node, self.mninfo, 102, COIN, pubkey)
        asset_unlock_tx_too_late = create_assetunlock(node, self.mninfo, 103, COIN, pubkey)
        asset_unlock_tx_duplicate_index = copy.deepcopy(asset_unlock_tx)
        asset_unlock_tx_duplicate_index.vout[0].nValue += COIN
        too_late_height = node.getblock(node.getbestblockhash())["height"] + 48

        self.check_mempool_result(tx=asset_unlock_tx, result_expected={'allowed': True})

        # validate that we calculate payload hash correctly: ask quorum forcely by message hash
        asset_unlock_tx_payload = CAssetUnlockTx()
        asset_unlock_tx_payload.deserialize(BytesIO(asset_unlock_tx.vExtraPayload))

        assert_equal(asset_unlock_tx_payload.quorumHash, int(self.mninfo[0].node.quorum("selectquorum", llmq_type_test, 'e6c7a809d79f78ea85b72d5df7e9bd592aecf151e679d6e976b74f053a7f9056')["quorumHash"], 16))

        self.send_tx(asset_unlock_tx)
        node.generate(1)
        self.sync_all()
        self.send_tx(asset_unlock_tx,
            expected_error = "Transaction already in block chain",
            reason = "double copy")

        block_asset_unlock = node.getbestblockhash()

        # mine next quorum, tx should be still accepted
        self.mine_quorum()
        # should stay same
        assert_equal(get_credit_pool_amount(node), locked_1 - COIN)
        self.check_mempool_result(tx=asset_unlock_tx_late, result_expected={'allowed': True})
        # should still stay same
        assert_equal(get_credit_pool_amount(node), locked_1 - COIN)
        self.send_tx(asset_unlock_tx_late)
        node.generate(1)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), locked_1 - 2 * COIN)

        # generate many blocks to make quorum far behind (even still active)
        self.slowly_generate_batch(too_late_height - node.getblock(node.getbestblockhash())["height"] - 1)
        self.check_mempool_result(tx=asset_unlock_tx_too_late, result_expected={'allowed': True})
        node.generate(1)
        self.sync_all()
        self.check_mempool_result(tx=asset_unlock_tx_too_late,
                result_expected={'allowed': False, 'reject-reason' : 'bad-assetunlock-too-late'})

        # two quorums later is too late because quorum is not active, reason should not be same
        self.mine_quorum()
        self.check_mempool_result(tx=asset_unlock_tx_too_late,
                result_expected={'allowed': False, 'reject-reason' : 'bad-assetunlock-not-active-quorum'})

        block_to_reconsider = node.getbestblockhash()
        self.log.info("Test block invalidation with asset unlock tx...")
        for inode in self.nodes:
            inode.invalidateblock(block_asset_unlock)
        assert_equal(get_credit_pool_amount(node), locked_1)
        # generate some new blocks
        self.slowly_generate_batch(50)
        assert_equal(get_credit_pool_amount(node), locked_1)
        for inode in self.nodes:
            inode.reconsiderblock(block_to_reconsider)
        assert_equal(get_credit_pool_amount(node), locked_1 - 2 * COIN)

        # Forcibly mine asset_unlock_tx_too_late and ensure block is invalid
        hh = node.getbestblockhash()
        best_block = node.getblock(hh)
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1


        cbb = create_coinbase(height, dip4_activated=True, v20_activated=True)
        block = create_block(tip, cbb, block_time, version=3)
        block.vtx.append(asset_unlock_tx_too_late)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        result = node.submitblock(block.serialize().hex())
        # Expect an error here
        expected_error = "bad-assetunlock-not-active-quorum"
        if result != expected_error:
            raise AssertionError('mining the block should have failed with error %s, but submitblock returned %s' % (expected_error, result))

        # ----

        node.generate(1)
        self.sync_all()

        assert_equal(get_credit_pool_amount(node), locked_1 -  2 * COIN)
        assert_equal(get_credit_pool_amount(node, block_hash_1), locked_1)

        # too big withdrawal should not be mined
        asset_unlock_tx_full = create_assetunlock(node, self.mninfo, 201, 1 + get_credit_pool_amount(node), pubkey)

        # Mempool doesn't know about the size of the credit pool, so the transaction will be accepted to mempool,
        # but won't be mined
        self.check_mempool_result(tx=asset_unlock_tx_full, result_expected={'allowed': True })

        txid_in_block = self.send_tx(asset_unlock_tx_full)
        node.generate(1)
        self.sync_all()
        # Check the tx didn't get mined
        try:
            node.gettransaction(txid_in_block)
            raise AssertionError("Transaction should not be mined")
        except JSONRPCException as e:
            assert "Invalid or non-wallet transaction id" in e.error['message']

        self.mempool_size += 1
        asset_unlock_tx_full = create_assetunlock(node, self.mninfo, 301, get_credit_pool_amount(node), pubkey)
        self.check_mempool_result(tx=asset_unlock_tx_full, result_expected={'allowed': True })

        txid_in_block = self.send_tx(asset_unlock_tx_full)
        node.generate(1)
        self.sync_all()
        # check txid_in_block was mined
        block = node.getblock(node.getbestblockhash())
        assert txid_in_block in block['tx']
        assert_equal(get_credit_pool_amount(node), 0)

        # test withdrawal limits
        # fast-forward to next day to reset previous limits
        self.log.info("Fast forward to the next day to reset all current unlock limits...")
        self.slowly_generate_batch(blocks_in_one_day  + 1)
        self.mine_quorum()

        total = get_credit_pool_amount(node)
        while total <= 10_500 * COIN:
            coin = coins.pop()
            to_lock = int(coin['amount'] * COIN) - tiny_amount
            total += to_lock
            tx = create_assetlock(node, coin, to_lock, pubkey)
            self.send_tx(tx)
        node.generate(1)
        self.sync_all()
        credit_pool_amount_1 = get_credit_pool_amount(node)
        assert_greater_than(credit_pool_amount_1, 10_500 * COIN)
        limit_amount_1 = 1000 * COIN
        # take most of limit by one big tx for faster testing and
        # create several tiny withdrawal with exactly 1 *invalid* / causes spend above limit tx
        amount_to_withdraw_1 = 1002 * COIN
        index = 400
        for next_amount in [990 * COIN, 3 * COIN, 3 * COIN, 3 * COIN, 3 * COIN]:
            index += 1
            asset_unlock_tx = create_assetunlock(node, self.mninfo, index, next_amount, pubkey)
            self.send_tx(asset_unlock_tx)
            if index == 401:
                node.generate(1)
        node.generate(1)
        self.sync_all()
        new_total = get_credit_pool_amount(node)
        amount_actually_withdrawn = total - new_total
        block = node.getblock(node.getbestblockhash())
        # Since we tried to withdraw more than we could
        assert_greater_than(amount_to_withdraw_1, amount_actually_withdrawn)
        # Check we tried to withdraw more than the limit
        assert_greater_than(amount_to_withdraw_1, limit_amount_1)
        # Check we didn't actually withdraw more than allowed by the limit
        assert_greater_than_or_equal(limit_amount_1, amount_actually_withdrawn)
        assert_greater_than(1000 * COIN, amount_actually_withdrawn)
        assert_equal(amount_actually_withdrawn, 999 * COIN)
        node.generate(1)
        self.sync_all()
        # one tx should stay in mempool for awhile until is not invalidated by height
        assert_equal(node.getmempoolinfo()['size'], 1)

        assert_equal(new_total, get_credit_pool_amount(node))
        self.log.info("Fast forward to next day again...")
        self.slowly_generate_batch(blocks_in_one_day - 2)
        # but should disappear later
        assert_equal(node.getmempoolinfo()['size'], 0)

        # new tx should be mined not this block, but next one
        # size of this transaction should be more than
        credit_pool_amount_2 = get_credit_pool_amount(node)
        limit_amount_2 = credit_pool_amount_2 // 10
        index += 1
        asset_unlock_tx = create_assetunlock(node, self.mninfo, index, limit_amount_2, pubkey)
        self.send_tx(asset_unlock_tx)
        node.generate(1)
        self.sync_all()
        assert_equal(new_total, get_credit_pool_amount(node))
        node.generate(1)
        self.sync_all()
        new_total -= limit_amount_2
        assert_equal(new_total, get_credit_pool_amount(node))
        # trying to withdraw more: should fail
        index += 1
        asset_unlock_tx = create_assetunlock(node, self.mninfo, index, COIN * 100, pubkey)
        self.send_tx(asset_unlock_tx)
        node.generate(1)
        self.sync_all()

        # all tx should be dropped from mempool because too far
        # but amount in credit pool should be still same after many blocks
        self.log.info("generate many blocks to be sure that mempool is empty afterwards...")
        self.slowly_generate_batch(60)
        assert_equal(new_total, get_credit_pool_amount(node))
        assert_equal(node.getmempoolinfo()['size'], 0)
if __name__ == '__main__':
    AssetLocksTest().main()
