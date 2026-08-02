Updated RPCs
------------

* `getcoinjoininfo` gained a `pending_inputs` field, reporting how many
  successfully mixed inputs are currently kept locked while waiting for the
  finalized mixing transaction spending them to be observed.

CoinJoin
--------

* After a mixing session completes successfully, the inputs a client
  contributed to it are no longer released as soon as the `DSCOMPLETE` message
  is processed. They stay locked until the wallet observes a transaction
  spending them, or for at most an hour if that transaction never propagates.
  Previously the completion message routinely overtook the trickle-relayed
  mixing transaction, leaving a window in which another session (with
  `-coinjoinmultisession=1`, where the one-block cooldown does not apply) could
  select and sign the very same inputs and produce a second, conflicting
  CoinJoin transaction.

  These locks are persisted, so they survive a restart. They are tracked in a
  new wallet database record, `cj_pending_obs`, which is written only when a
  mixing session completes successfully. Older clients loading such a wallet
  ignore the record, counting it as an unknown record; the accompanying
  `lockedutxo` entries are understood by them regardless, so the inputs stay
  locked either way. Locks the user set themselves via `lockunspent` are never
  adopted or released by this mechanism, and unlocking a pending input manually
  purges it from the pending set.
