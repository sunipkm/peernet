# PeerNet Changelog
9. [2022-10-31] (v3.0.0) C API update: peer_errno variable removed to ensure Windows compatibility. pypeernet updated to v2.0.
8. [2022-09-24] (v.2.2.0) C API update: peer_stop function removed as it is unsafe. pypeernet is NOT affected.
7. [2022-09-24] (v.2.1.4) Backend updates for (pypeernet)[https://github.com/sunipkm/pypeernet].
6. [2022-09-23] (v.2.1.3) Peer collision detection was fixed after authentication update.
5. [2022-09-21] (v.2.1.2) peernet_errno extern was not declared.
4. [2022-09-21] (v.2.1.1) Fixed doxygen, small memory leak.
3. [2022-09-21] (v2.1.0) Extension to second API, callback functions now contain size of remote data for copying (basically making it useful for things other than strings.)
2. [2022-09-21] (v.2.0.0) Second stable API, added authentication support, disabled requesting silent peers to leave by default.
1. [2022-09-20] (v1.0.0) First stable API. 