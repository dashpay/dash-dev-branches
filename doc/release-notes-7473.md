Notable changes
===============

* Masternode operator key uniqueness is now enforced per key rather than per BLS
  encoding. After the v24 hard fork activates, registering or updating to an
  operator public key already used by another masternode is rejected regardless of
  which BLS scheme (legacy or basic) either side is encoded under, closing a gap
  where the same key could be claimed twice under different encodings.

Updated RPCs
------------

* After the v24 hard fork activates, a legacy (LegacyBLS) masternode migrates to the
  basic BLS scheme *in place* when its state version is raised, keeping the same
  operator key: the stored operator public key is re-encoded from the legacy to the
  basic scheme, with no key rotation required. `protx update_service` and
  `protx update_registrar` build the corresponding basic-scheme migration
  transaction for a legacy masternode, and the masternode is no longer PoSe-banned by
  the change. The `..._legacy` RPC variants keep the masternode on the legacy scheme.
  Previously a legacy masternode could not move to the basic scheme without
  effectively rotating its operator key, and `update_registrar` clamped the
  transaction version silently.

These changes are gated on the v24 deployment and have no effect until it activates
(v24 is not yet scheduled on mainnet or testnet).
