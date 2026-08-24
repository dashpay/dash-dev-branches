Wallet changes
--------------

- CoinJoin denomination counts, average mixing rounds and the normalized
  anonymized balance no longer include outputs of transactions that cannot
  confirm as they stand: conflicted ones, and ones that were abandoned, never
  broadcast, or rejected from the mempool. Previously such outputs inflated
  these figures, which could make the wallet create fewer denominations than
  intended and report mixing progress that did not match the coins it could
  actually use. (#7634)
