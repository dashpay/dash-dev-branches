GUI changes
-----------

- Dash-Qt now labels masternode registration and update transactions in the
  transaction history as **Masternode Registration** and **Masternode Update**
  instead of generic "Payment to yourself" rows. A new **Masternode** filter
  shows only these operations. The amount shown is the transaction's net effect
  on your wallet (for example, the network fee on a self-funded registration).
  (#7595)
