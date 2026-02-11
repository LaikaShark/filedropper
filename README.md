usage: filedropper [-h] {send,receive,relay} ...

Peer-to-peer file sharing with five-word codes.

positional arguments:
  {send,receive,relay}
    send                Send a file or directory
    receive             Receive a file or directory
    relay               Run a relay/rendezvous server

options:
  -h, --help            show this help message and exit

examples:
  filedropper send photo.jpg
  filedropper send ./my-project/
  filedropper receive alpha-bravo-charlie-delta-echo
  filedropper receive alpha bravo charlie delta echo
  filedropper receive alpha-bravo-charlie-delta-echo -o ~/Downloads

relay mode (NAT punchthrough):
  filedropper relay -p 9999
  filedropper send --relay myserver:9999 photo.jpg
  filedropper receive --relay myserver:9999 alpha-bravo-charlie-delta-echo

notes:
  Without --relay, both sender and receiver must be on the same local
  network, or the sender must have a publicly reachable IP (use --ip
  and --port for port-forwarding scenarios).

  With --relay, transfers work across NATs.  A relay server must be
  running on a publicly reachable host.  The tool will attempt UDP
  hole punching for direct transfer, falling back to TCP relay.
