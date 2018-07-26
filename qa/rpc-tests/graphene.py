#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


import pdb
from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import create_block, create_coinbase
from test_framework.siphash import siphash256
from test_framework.script import CScript, OP_TRUE

'''
GrapheneBlockTest -- test graphene blocks
'''

# TestNode: A peer we use to send messages to bitcoind, and store responses.
class TestNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.last_grblk = []
        self.last_inv = None
        self.last_grblktx = None
        self.last_getgrblktx = None
        self.last_getgrblk = None
        self.last_block = None
        self.get_getheaders = None
        self.block_announced = False
        # Store the hashes of blocks we've seen announced.
        # This is for synchronizing the p2p message traffic,
        # so we can eg wait until a particular block is announced.
        self.set_announced_blockhashes = set()

    def on_grblk(self, conn, message):
        self.last_grblk = message
        self.block_announced = True

    def on_inv(self, conn, message):
        want = msg_getgrblk()
        for i in message.inv
            if i.type != 0:
                want.inv.apend(i)
        if len(want.inv):
            conn.send_message(want)

    def on_grblktx(self, conn, message):
        self.last_grblktx = message

    def on_headers(self, conn, message):
        self.last_headers = message
        self.block_announced = True
        for x in self.last_headers.headers:
            x.calc_sha256()
            self.set_announced_blockhashes.add(x.sha256)

    def on_getgrblktx(self, conn, message):
        self.last_getgrblktx = message

    def on_getgrblk(self, conn, message):
        self.last_getgrblk =  message

    def on_block(self, conn, message):
        self.last_block = message

    def on_getheaders(self, conn, message):
        self.last_getheaders = message

    # Requires caller to hold mininode_lock
    def received_block_announcement(self):
        return self.block_announced

    def clear_block_announcement(self):
        with mininode_lock:
            self.block_announced = False
            self.last_inv = None
            self.last_headers = None
            self.last_grblk  = None

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.connection.send_message(msg)

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_message(headers_message)

    def request_headers_and_sync(self, locator, hashstop=0):
        self.clear_block_announcement()
        self.get_headers(locator, hashstop)
        assert(wait_until(self.received_block_announcement, timeout=30))
        assert(self.received_block_announcement())
        self.clear_block_announcement()

    # Block until a block announcement for a particular block hash is
    # received.
    def wait_for_block_announcement(self, block_hash, timeout=30):
        def received_hash():
            return (block_hash in self.set_announced_blockhashes)
        return wait_until(received_hash, timeout=timeout)

class GrapheneBlockTest(BitcoinTestFramework):
    def __init__(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.utxos = []

    def setup_network(self, split=False):
        node_opts = [ "-debug", "-use-grapheneblocks=1" ]

        self.nodes = [
            start_node(0, self.options.tmpdir, node_opts),
            start_node(1, self.options.tmpdir, node_opts),
        ]

        connect_nodes(self.nodes[0], 1)

    def build_block_on_tip(self, node):
        height = node.getblockcount()
        tip = node.getbestblockhash()
        mtp = node.getblockheader(tip)['mediantime']
        block = create_block(int(tip, 16), create_coinbase(height + 1), mtp + 1)
        block.solve()
        return block

    def make_utxos(self):
        # Doesn't matter which node we use, just use node0.
        block = self.build_block_on_tip(self.nodes[0])
        self.test_node.send_and_ping(msg_block(block))
        assert(int(self.nodes[0].getbestblockhash(), 16) == block.sha256)
        self.nodes[0].generate(100)

        total_value = block.vtx[0].vout[0].nValue
        out_value = total_value // 10
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(block.vtx[0].sha256, 0), b''))
        for i in range(10):
            tx.vout.append(CTxOut(out_value, CScript([OP_TRUE])))
        tx.rehash()

        block2 = self.build_block_on_tip(self.nodes[0])
        block2.vtx.append(tx)
        block2.hashMerkleRoot = block2.calc_merkle_root()
        block2.solve()
        self.test_node.send_and_ping(msg_block(block2))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block2.sha256)
        self.utxos.extend([[tx.sha256, i, out_value] for i in range(10)])
        return

    # The first message should be getgrblk
    # def test_getgrblk(self, node, test_node, old_node=None):

    def check_announcement_of_new_block(node, peer, predicate):
        peer.clear_block_announcement()
        block_hash = int(node.generate(1)[0], 16)
        peer.wait_for_block_announcement(block_hash, timeout=30)
        assert(peer.block_announced)
        assert(got_message)

        with mininode_lock:
            assert predicate(peer), (
                    "block_hash={!r}, grblk={!r}, inv={!r}".format(
                        block_hash, peer.last_grblk, peer.last_inv))

    # We shouldn't get any block announcements via cmpctblock yet.
    check_announcement_of_new_block(node, test_node, lambda p: p.last_grblk is None)

    # Try one more time, this time after requesting headers.
    test_node.request_headers_and_sync(locator=[tip])
    check_announcement_of_new_block(node, test_node, lambda p: p.last_grblk
            is None and p.last_inv is not None)

    # Test a few ways of using sendcmpct that should NOT
    # result in compact block announcements.
    # Before each test, sync the headers chain.
    test_node.request_headers_and_sync(locator=[tip])

    def run_test(self):
        pdb.set_trace()
        self.test_node = TestNode()
        self.second_node = TestNode()
        self.old_node = TestNode()

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node))
        connections.append(NodeConn('127.0.0.1', p2p_port(1), self.nodes[1],
                    self.second_node, services=NODE_GRAPHENE ))
        connections.append(NodeConn('127.0.0.1', p2p_port(1), self.nodes[1],
                    self.old_node, services=NODE_GRAPHENE ))
        self.test_node.add_connection(connections[0])
        self.second_node.add_connection(connections[1])
        self.old_node.add_connection(connections[2])

        NetworkThread().start()  # Start up network handling in another thread

        # Test logic begins here
        self.test_node.wait_for_verack()

        # We will need UTXOs to construct transactions in later tests.
        self.make_utxos()

        print("Running tests:")


if __name__ == '__main__':
    GrapheneBlockTest().main()
