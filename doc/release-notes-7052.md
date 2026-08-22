P2P and network changes
-----------------------

- The protocol version was bumped to 70241. The `dsa` message gained a
  version-gated flags field declaring which mixing direction a
  participant intends. A session commits to carrying promotion/demotion
  entries only once a participant is admitted that actually declared one,
  and it becomes closed to pre-70241 clients only from that point on;
  conversely, a session that has already admitted a pre-70241 client
  refuses later promotion/demotion participants. Either way the refusal
  happens at acceptance time, before any collateral is committed, so a
  client doing ordinary 1:1 mixing is never turned away from a session
  simply because of who opened it. Unbalanced (promotion/demotion) DSTXes
  are only announced as `dstx` to peers at protocol 70241 or newer, since
  older peers would reject them as structurally invalid and penalize the
  relayer; those peers are sent a plain `tx` announcement instead, so
  they still receive the transaction without the mixing metadata they
  cannot parse. (#7052)

- A mixing session only completes once each side of its denomination is
  occupied by nobody or by at least two participants, since coins are
  only concealed by other coins of the same size on the same side. A
  session that attracts a lone promotion or demotion participant and no
  counterpart therefore waits, and expires in the queue stage without
  charging anyone's collateral, rather than publishing a transaction that
  would identify that participant's coins. Because admission relies on
  the declared directions, a participant whose entry deviates from what
  it declared has its collateral consumed. (#7052)

Wallet
------

- CoinJoin can now promote and demote between adjacent standard
  denominations within a mixing session after V24 activation.
  Promotion combines 10 inputs of one denomination into 1 output of the
  next larger denomination, while demotion splits 1 input into 10
  outputs of the next smaller denomination. Pre-V24 behavior remains
  unchanged. (#7052)

- Conversions only spend fully-mixed coins, and their outputs start
  mixing over from zero rounds. The 10:1 shape of a conversion publicly
  clusters one participant's coins even inside a mixing transaction, so
  a converted coin is not treated as mixed: it re-enters mixing at its
  new denomination and disperses normally, while the histories of the
  fully-mixed coins that fed the conversion remain protected. (#7052)
