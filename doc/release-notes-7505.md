Removed command-line options
---------------------------

* `-minsporkkeys` has been removed. Multi-key ("M-of-N") spork signing was never
  deployed on any network — every chain shipped a single spork address with a
  threshold of one — and the implementation has been removed. (dash#7505)

Updated command-line options
----------------------------

* `-sporkaddr` now configures a single spork address. Previously it could be
  specified multiple times to configure a set of valid spork signers.
  (dash#7505)

Notes
-----

* The `sporks.dat` cache format changed. Caches written by previous versions are
  discarded on startup and sporks are re-synced from peers, as is already the
  case for any cache-format change. (dash#7505)
