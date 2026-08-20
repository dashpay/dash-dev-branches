P2P and network changes
-----------------------

- `getqrinfo` requests now carry at most 4096 `baseBlockHashes`. A request
  with more is rejected before it is parsed and the sending peer is penalised
  as misbehaving. No known client sends more than a handful; the previous
  format accepted up to 98304 entries in one message, which an
  unauthenticated peer could use to make the node do work proportional to
  the list size while holding `cs_main`. The `quorum rotationinfo` RPC
  applies the same limit and returns an error when it is exceeded. (#7629)
