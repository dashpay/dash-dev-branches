RPC changes
-----------

- Normal and Evo `protx` registration and maintenance commands now share a
  typed provider-transaction implementation with other wallet frontends. RPC
  names and successful result formats are unchanged. Fixed: when a wallet
  cannot completely sign the inputs it selected (e.g. `protx register_submit`
  run in a different wallet than the one that prepared the registration),
  the command now fails with a clear wallet error naming the problem instead
  of reporting success with a partially signed transaction or attempting a
  broadcast that failed mempool acceptance with a bare `-26` error. The
  external-signing workflow (`protx register_prepare` followed by
  `protx register_submit`) is unchanged.
  `protx update_service` on a masternode whose state does not yield a usable
  default fee source now returns an explicit "specify feeSourceAddress"
  parameter error instead of an internal error. (#7600)
