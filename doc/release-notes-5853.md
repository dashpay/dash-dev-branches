Added RPC
--------

- `dkginfo` RPC returns information about DKGs:
`nActiveDKGs`: Total number of active DKG sessions.
`nextDKG`: If `nActiveDKGs` is 0, then `nextDKG` indicates the number of blocks until the next potential DKG session.

Note: This RPC is enabled only for Masternodes, and it is expected to work only when `SPORK_17_QUORUM_DKG_ENABLED` spork is ON.