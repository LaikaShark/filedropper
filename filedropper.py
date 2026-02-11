#!/usr/bin/env python3
"""
filedropper - Peer-to-peer file sharing with five-word codes.

Usage:
    filedropper.py send <path>                       Send (LAN direct)
    filedropper.py send --relay host:port <path>     Send (NAT punchthrough)
    filedropper.py receive <code> [-o DIR]           Receive (LAN direct)
    filedropper.py receive --relay host:port <code>  Receive (NAT punchthrough)
    filedropper.py relay [-p PORT]                   Run relay server

Zero external dependencies - uses only the Python standard library.
"""

import argparse
import hashlib
import json
import os
import secrets
import select
import socket
import struct
import sys
import tarfile
import tempfile
import threading
import time

# ---------------------------------------------------------------------------
# Word list: ~1000 common, short English words used to encode IP:port pairs.
# Sorted and deduplicated at import time.  We need >= 776 unique words so
# that  W^5 >= 2^48  (48 bits encodes an IPv4 address + TCP port).
# ---------------------------------------------------------------------------
_RAW_WORDS = """
able acid acre aged aide airy ally also arch area army aunt auto avid axle
back bail bait bake bald bale ball band bane bank bare bark barn base bath
bead beak beam bean bear beat beef beer bell belt bend bent best bike bill
bind bird bite blow blue blur boar boat body bold bolt bomb bond bone book
boom boot bore born both bowl bran bred brew brim buck bulb bulk bull bump
burn bush bust byte cafe cage cake calf calm came camp cane cape card care
carp cart case cash cast cave cell char chat chin chip chop cite clad clam
clan clap claw clay clip clod clog club clue coal coat code coil coin cold
colt comb cone cook cool cope copy cord core cork corn cost coup cove crab
crew crop crow cube cult curb cure curl cute dale dame damp dare dark dart
dash dawn deal dear deck deed deem deep deer delt dent deny desk dial dice
dill dime dine dire dirt disc dish disk dock dome done doom door dose dove
down doze drab drag draw drip drop drum dual duck duel dull dump dune dusk
dust duty each earl earn ease east edge edit emit envy epic euro even ever
evil exam exit face fact fade fail fair fake fall fame fang fare farm fast
fate fawn fear feat feed feel fell felt fend fern file fill film find fine
fire firm fish fist five flag flap flat flaw flea fled flee flew flex flip
flit flog flop flow foam foil fold folk fond font food fool foot ford fore
fork form fort foul four fowl free frog from fuel full fume fund fuse fury
fuss gait gale gall game gang gape garb gate gave gaze gear gene gift gild
gill gilt gist give glad glen glib glob glow glue glum glut gnaw goad goal
goat goes gold golf gone good gore gown grab gram gras gray grew grid grim
grin grip grit grow grub gulf gull gulp gush gust hack hail hair hale half
hall halt hand hang hare harm harp hash hate haul have hawk haze head heal
heap hear heat heed heel held help hemp herb herd hero hike hill hilt hind
hint hire hive hold hole home hone hood hoof hook hoop hope horn hose host
hour howl huge hull hump hung hunt hurl hurt husk hymn idea inch into iris
iron isle itch item jack jade jail jazz jean jeer jest jilt jive join joke
jolt jump junk jury just keen keep kelp kept keys kick kill kind king kiss
kite knob knot know lace lack lacy laid lair lake lamb lame lamp land lane
lard lark lash lass last late lawn lead leaf leak lean leap left lend lens
lent less liar lice lick lied lieu life lift like limb lime limp line link
lint lion list live load loaf loam loan lobe lock lode loft lone long look
loom loop lord lore lose loss lost loud love luck lull lump lure lurk lush
lust lynx mace made maid mail main make male malt mane many mare mark mash
mask mass mast mate maze mead meal mean meat meek meet meld melt memo mend
menu mere mesh mess mice mild mile milk mill mime mind mine mint mire miss
mist mite mitt moan moat mock mode mold mole monk mood moon moor more moss
most moth move much muck mule mull murk muse mush must mute myth name nape
navy near neat neck need nest news next nice nine node none noon norm nose
note noun nude null oath oats obey odds once only onto open oral oven over
pace pack paid pail pain pair pale palm pane pang park part pass past path
pave pawn peak peal pear peat peel peer pelt pend perk pest pick pier pike
pile pill pine pink pipe plan play plea plod plot plow ploy plug plum plus
poem poet poke pole poll polo pomp pond pool poor pope pore pork port pose
post pour pout pray prey prod prop prow pull pulp pump punk pure push quad
quay quip quit quiz race rack raft rage raid rail rain rake ramp rang rank
rare rash rate rave read real ream reap reed reef reel rein rely rent rest
rice rich ride rift rill rime rind ring riot ripe rise risk road roam roar
robe rock rode role roll roof room root rope rose rosy rout rove ruin rule
rump rung ruse rush rust sack safe sage said sail sake sale salt same sand
sane sash save scan scar seal seam sear seat sect seed seek seem self sell
send sent sewn shed shin ship shoe shop shot show shut sick side sift sigh
sign silk sill silt sing sink sire site size skim skin skip slab slag slam
slap slat sled slew slim slit slob slog slop slot slow slug slum smog snap
snip snob snow snub snug soak soap soar sock soda sofa soft soil sold sole
some song soon soot sore sort soul soup sour span spar sped spin spit spot
spry spur stab stag star stay stem step stew stir stop stow stub stud stun
such suit sulk sump sung sunk sure surf swan swap sway swim tack tact tail
take tale talk tall tame tang tank tape tarn task taut teal team tear tell
tend tens tent term test text than them then they thin this tick tide tidy
tied tier tile till tilt time tine tiny tire toad toil told toll tomb tone
took tool tops tore torn toss tour town trap tray tree trek trim trio trip
trod trot true tube tuck tuft tuna tune turf turn tusk twig twin type ugly
undo unit unto upon urge used vain vale vane vary vase vast veil vein vent
verb very vest vial vice view vine visa void volt vote wade wage wail wait
wake walk wall wand want ward warm warn warp wart wary wash wasp wave wavy
wean wear weed week weld well welt went west what when whim whip whom wick
wide wife wild will wilt wind wine wing wink wipe wire wise wish wisp with
woke wolf womb wood wool word wore work worm worn wove wrap wren yard yarn
year yell yoga yoke yore your zeal zero zinc zone zoom
"""

WORDS = sorted(set(_RAW_WORDS.lower().split()))
assert len(WORDS) >= 776, f"Need >= 776 unique words, got {len(WORDS)}"

CHUNK = 65536  # 64 KB transfer chunks


# ---------------------------------------------------------------------------
# Generalized word encoding
# ---------------------------------------------------------------------------

def words_encode(num, count=5):
    """Encode a non-negative integer as *count* words from the word list."""
    W = len(WORDS)
    parts = []
    for _ in range(count):
        parts.append(WORDS[num % W])
        num //= W
    return "-".join(parts)


def words_decode(code, count=5):
    """Decode a word code back to a non-negative integer."""
    raw = code.strip().lower().replace("-", " ").replace(",", " ")
    parts = raw.split()
    if len(parts) != count:
        raise ValueError(f"Expected {count} words, got {len(parts)}: {parts}")

    W = len(WORDS)
    num = 0
    for w in reversed(parts):
        if w not in WORDS:
            raise ValueError(f"Unknown word: '{w}'")
        num = num * W + WORDS.index(w)
    return num


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_local_ip():
    """Best-effort detection of the machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def encode_addr(ip, port):
    """Encode an IPv4 address + port as a five-word code."""
    octets = [int(o) for o in ip.split(".")]
    num = 0
    for o in octets:
        num = (num << 8) | o
    num = (num << 16) | port          # 48-bit value
    return words_encode(num)


def decode_addr(code):
    """Decode a five-word code back to (ip, port)."""
    num = words_decode(code)
    port = num & 0xFFFF
    num >>= 16
    octets = []
    for _ in range(4):
        octets.append(num & 0xFF)
        num >>= 8
    ip = ".".join(str(o) for o in reversed(octets))
    return ip, port


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def recv_exact(sock, n):
    """Receive exactly *n* bytes from *sock*."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), CHUNK))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def fmt_size(n):
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def progress(current, total, width=40):
    """Print a progress bar on a single line (overwrites itself)."""
    if total == 0:
        pct = 1.0
    else:
        pct = current / total
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(
        f"\r  [{bar}] {pct * 100:5.1f}%  {fmt_size(current)} / {fmt_size(total)}"
    )
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Tarball helpers (for directories)
# ---------------------------------------------------------------------------

def tar_directory(path):
    """Compress a directory into a temporary .tar.gz file.  Returns the path."""
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        with tarfile.open(fileobj=tmp, mode="w:gz") as tar:
            tar.add(path, arcname=os.path.basename(path))
        tmp.close()
        return tmp.name
    except Exception:
        tmp.close()
        os.unlink(tmp.name)
        raise


def safe_extract(tar, dest):
    """Extract a tarball with path-traversal protection."""
    dest = os.path.realpath(dest)
    for member in tar.getmembers():
        member_path = os.path.realpath(os.path.join(dest, member.name))
        if not (member_path.startswith(dest + os.sep) or member_path == dest):
            raise ValueError(f"Blocked path traversal attempt: {member.name}")
    tar.extractall(path=dest)


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------

def sha256_file(path):
    """Return the hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Relay signaling helpers (newline-delimited JSON over TCP)
# ---------------------------------------------------------------------------

def relay_send_msg(sock, msg):
    """Send a JSON message terminated by newline over TCP."""
    data = json.dumps(msg).encode("utf-8") + b"\n"
    sock.sendall(data)


def relay_recv_msg(sock):
    """Receive one newline-delimited JSON message (byte-at-a-time to avoid
    over-reading past the newline into file data)."""
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("Relay connection closed")
        if b == b"\n":
            break
        buf.extend(b)
    return json.loads(buf.decode("utf-8"))


# ---------------------------------------------------------------------------
# TCP file transfer helpers (shared by LAN mode and relay fallback)
# ---------------------------------------------------------------------------

def tcp_send_file(sock, data_path, metadata):
    """Send header + file data over an already-connected TCP socket."""
    header = json.dumps(metadata).encode("utf-8")
    sock.sendall(struct.pack("!I", len(header)))
    sock.sendall(header)

    data_size = metadata["size"]
    sent = 0
    with open(data_path, "rb") as f:
        while sent < data_size:
            chunk = f.read(min(CHUNK, data_size - sent))
            if not chunk:
                break
            sock.sendall(chunk)
            sent += len(chunk)
            progress(sent, data_size)
    print()


def tcp_recv_file(sock, output_dir):
    """Receive header + file data from a TCP socket.  Returns (name, ftype)."""
    header_len = struct.unpack("!I", recv_exact(sock, 4))[0]
    header = json.loads(recv_exact(sock, header_len).decode("utf-8"))

    name = header["name"]
    size = header["size"]
    ftype = header["type"]
    expected_hash = header.get("sha256", "")

    print(f"Receiving: {name}{'/' if ftype == 'directory' else ''}"
          f"  ({fmt_size(size)})  [{ftype}]")

    if ftype == "directory":
        tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        out_path = tmp.name
        tmp.close()
    else:
        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(output_dir, name)
        if os.path.exists(out_path):
            base, ext = os.path.splitext(out_path)
            i = 1
            while os.path.exists(f"{base}_{i}{ext}"):
                i += 1
            out_path = f"{base}_{i}{ext}"

    hasher = hashlib.sha256()
    received = 0
    with open(out_path, "wb") as f:
        while received < size:
            to_read = min(CHUNK, size - received)
            chunk = sock.recv(to_read)
            if not chunk:
                raise ConnectionError("Connection lost during transfer")
            f.write(chunk)
            hasher.update(chunk)
            received += len(chunk)
            progress(received, size)

    actual_hash = hasher.hexdigest()
    print()

    if expected_hash:
        if actual_hash != expected_hash:
            print("WARNING: Checksum mismatch — file may be corrupted!")
            print(f"  Expected : {expected_hash}")
            print(f"  Received : {actual_hash}")
        else:
            print(f"Checksum OK: {actual_hash[:16]}...")

    if ftype == "directory":
        print(f"Extracting to: {os.path.abspath(output_dir)}/")
        with tarfile.open(out_path, "r:gz") as tar:
            safe_extract(tar, output_dir)
        os.unlink(out_path)
        print(f"Done! Directory saved: {os.path.join(output_dir, name)}/")
    else:
        print(f"Done! File saved: {out_path}")

    return name, ftype


# ---------------------------------------------------------------------------
# UDP hole punching
# ---------------------------------------------------------------------------

def udp_discover(sock, relay_addr, session_id):
    """Send UDP DISCOVER to relay server, receive our mapped public address."""
    msg = json.dumps({"type": "discover", "session": session_id}).encode("utf-8")
    for _ in range(3):
        sock.sendto(msg, relay_addr)
        ready, _, _ = select.select([sock], [], [], 2.0)
        if ready:
            data, addr = sock.recvfrom(1024)
            try:
                resp = json.loads(data.decode("utf-8"))
                if resp.get("type") == "mapped":
                    return resp["ip"], resp["port"]
            except (json.JSONDecodeError, KeyError):
                continue
    raise TimeoutError("UDP discovery failed — no response from relay")


def udp_punch(sock, peer_addr, session_id, timeout=5):
    """Attempt UDP hole punching with peer.  Returns True if successful."""
    peer = (peer_addr["ip"], peer_addr["port"])
    punch_msg = json.dumps({"type": "punch", "session": session_id}).encode("utf-8")
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        sock.sendto(punch_msg, peer)
        remaining = max(0.01, deadline - time.monotonic())
        ready, _, _ = select.select([sock], [], [], min(0.2, remaining))
        if ready:
            data, addr = sock.recvfrom(1024)
            try:
                msg = json.loads(data.decode("utf-8"))
                if msg.get("type") == "punch":
                    # Send a few more to make sure peer receives ours too
                    for _ in range(3):
                        sock.sendto(punch_msg, addr)
                        time.sleep(0.05)
                    return True
            except (json.JSONDecodeError, KeyError):
                continue
    return False


# ---------------------------------------------------------------------------
# RUDP - Reliable UDP transfer protocol
# ---------------------------------------------------------------------------
# Packet format: [1B type][4B seq][payload]
# Types:
RUDP_HEADER     = 0
RUDP_HEADER_ACK = 1
RUDP_DATA       = 2
RUDP_ACK        = 3
RUDP_FIN        = 4
RUDP_FIN_ACK    = 5

RUDP_MAX_PAYLOAD = 1300
RUDP_WINDOW      = 128
RUDP_TIMEOUT     = 0.5   # retransmit timeout in seconds
RUDP_HDR_SIZE    = 5     # 1 byte type + 4 bytes seq


def _rudp_pack(ptype, seq, payload=b""):
    return struct.pack("!BI", ptype, seq) + payload


def _rudp_unpack(data):
    if len(data) < RUDP_HDR_SIZE:
        return None, None, None
    ptype, seq = struct.unpack("!BI", data[:RUDP_HDR_SIZE])
    payload = data[RUDP_HDR_SIZE:]
    return ptype, seq, payload


def rudp_send_file(sock, addr, data_path, metadata):
    """Send a file reliably over UDP to addr using sliding window."""
    # Send HEADER with metadata
    header_payload = json.dumps(metadata).encode("utf-8")
    header_pkt = _rudp_pack(RUDP_HEADER, 0, header_payload)

    # Retry until HEADER_ACK
    for attempt in range(30):
        sock.sendto(header_pkt, addr)
        ready, _, _ = select.select([sock], [], [], RUDP_TIMEOUT)
        if ready:
            data, _ = sock.recvfrom(65535)
            ptype, _, _ = _rudp_unpack(data)
            if ptype == RUDP_HEADER_ACK:
                break
    else:
        raise TimeoutError("Peer did not acknowledge header")

    # Read entire file into chunks
    data_size = metadata["size"]
    chunks = []
    with open(data_path, "rb") as f:
        while True:
            chunk = f.read(RUDP_MAX_PAYLOAD)
            if not chunk:
                break
            chunks.append(chunk)

    total_chunks = len(chunks)
    base = 0        # oldest unacked
    next_seq = 0    # next to send

    while base < total_chunks:
        # Send window
        while next_seq < total_chunks and next_seq < base + RUDP_WINDOW:
            pkt = _rudp_pack(RUDP_DATA, next_seq, chunks[next_seq])
            sock.sendto(pkt, addr)
            next_seq += 1

        # Wait for ACKs
        last_send_time = time.monotonic()
        while base < total_chunks:
            remaining = RUDP_TIMEOUT - (time.monotonic() - last_send_time)
            if remaining <= 0:
                # Timeout — Go-Back-N: resend from base
                next_seq = base
                break
            ready, _, _ = select.select([sock], [], [], remaining)
            if ready:
                data, _ = sock.recvfrom(65535)
                ptype, ack_seq, _ = _rudp_unpack(data)
                if ptype == RUDP_ACK:
                    # Cumulative ACK: ack_seq = next expected by receiver
                    if ack_seq > base:
                        base = ack_seq
                        last_send_time = time.monotonic()
                        # Show progress
                        progress(min(base * RUDP_MAX_PAYLOAD, data_size), data_size)

        progress(min(base * RUDP_MAX_PAYLOAD, data_size), data_size)

    # Send FIN
    fin_pkt = _rudp_pack(RUDP_FIN, total_chunks)
    for _ in range(20):
        sock.sendto(fin_pkt, addr)
        ready, _, _ = select.select([sock], [], [], RUDP_TIMEOUT)
        if ready:
            data, _ = sock.recvfrom(65535)
            ptype, _, _ = _rudp_unpack(data)
            if ptype == RUDP_FIN_ACK:
                break

    print()


def rudp_recv_file(sock, peer_addr, output_dir):
    """Receive a file reliably over UDP.  Returns (name, ftype)."""
    addr = (peer_addr["ip"], peer_addr["port"])

    # Wait for HEADER
    header = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], 1.0)
        if ready:
            data, src = sock.recvfrom(65535)
            ptype, _, payload = _rudp_unpack(data)
            if ptype == RUDP_HEADER:
                header = json.loads(payload.decode("utf-8"))
                addr = src  # use actual source address
                sock.sendto(_rudp_pack(RUDP_HEADER_ACK, 0), addr)
                break
    if header is None:
        raise TimeoutError("Did not receive header from peer")

    name = header["name"]
    size = header["size"]
    ftype = header["type"]
    expected_hash = header.get("sha256", "")

    print(f"Receiving: {name}{'/' if ftype == 'directory' else ''}"
          f"  ({fmt_size(size)})  [{ftype}]")

    # Determine output path
    if ftype == "directory":
        tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        out_path = tmp.name
        tmp.close()
    else:
        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(output_dir, name)
        if os.path.exists(out_path):
            base_name, ext = os.path.splitext(out_path)
            i = 1
            while os.path.exists(f"{base_name}_{i}{ext}"):
                i += 1
            out_path = f"{base_name}_{i}{ext}"

    # Receive data chunks
    expected_seq = 0
    ooo_buffer = {}  # out-of-order buffer
    hasher = hashlib.sha256()
    received_bytes = 0

    with open(out_path, "wb") as f:
        done = False
        deadline = time.monotonic() + 300  # 5 minute overall timeout
        while not done and time.monotonic() < deadline:
            ready, _, _ = select.select([sock], [], [], 1.0)
            if not ready:
                continue
            data, src = sock.recvfrom(65535)
            ptype, seq, payload = _rudp_unpack(data)

            if ptype == RUDP_DATA:
                if seq == expected_seq:
                    f.write(payload)
                    hasher.update(payload)
                    received_bytes += len(payload)
                    expected_seq += 1
                    # Flush buffered in-order packets
                    while expected_seq in ooo_buffer:
                        p = ooo_buffer.pop(expected_seq)
                        f.write(p)
                        hasher.update(p)
                        received_bytes += len(p)
                        expected_seq += 1
                    progress(min(received_bytes, size), size)
                elif seq > expected_seq:
                    ooo_buffer[seq] = payload
                # Send cumulative ACK
                sock.sendto(_rudp_pack(RUDP_ACK, expected_seq), src)

            elif ptype == RUDP_FIN:
                # Flush any remaining buffered
                while expected_seq in ooo_buffer:
                    p = ooo_buffer.pop(expected_seq)
                    f.write(p)
                    hasher.update(p)
                    received_bytes += len(p)
                    expected_seq += 1
                sock.sendto(_rudp_pack(RUDP_FIN_ACK, expected_seq), src)
                done = True

            elif ptype == RUDP_HEADER:
                # Resend HEADER_ACK (sender didn't get it)
                sock.sendto(_rudp_pack(RUDP_HEADER_ACK, 0), src)

    actual_hash = hasher.hexdigest()
    print()

    if expected_hash:
        if actual_hash != expected_hash:
            print("WARNING: Checksum mismatch — file may be corrupted!")
            print(f"  Expected : {expected_hash}")
            print(f"  Received : {actual_hash}")
        else:
            print(f"Checksum OK: {actual_hash[:16]}...")

    if ftype == "directory":
        print(f"Extracting to: {os.path.abspath(output_dir)}/")
        with tarfile.open(out_path, "r:gz") as tar:
            safe_extract(tar, output_dir)
        os.unlink(out_path)
        print(f"Done! Directory saved: {os.path.join(output_dir, name)}/")
    else:
        print(f"Done! File saved: {out_path}")

    return name, ftype


# ---------------------------------------------------------------------------
# Relay server
# ---------------------------------------------------------------------------

def cmd_relay(args):
    """Run a relay/rendezvous server for NAT punchthrough."""
    port = args.port

    # Sessions: session_id -> {"sender": sock, "receiver": sock,
    #                          "sender_udp": (ip, port), "receiver_udp": ...}
    sessions = {}
    sessions_lock = threading.Lock()

    # --- UDP listener (address discovery) ---
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", port))

    def udp_listener():
        while True:
            try:
                data, addr = udp_sock.recvfrom(1024)
                msg = json.loads(data.decode("utf-8"))
                if msg.get("type") == "discover":
                    sid = msg["session"]
                    resp = json.dumps({
                        "type": "mapped",
                        "ip": addr[0],
                        "port": addr[1],
                    }).encode("utf-8")
                    udp_sock.sendto(resp, addr)
                    # Store the UDP mapping for this session
                    role = msg.get("role", "")
                    with sessions_lock:
                        if sid in sessions:
                            sessions[sid][f"{role}_udp"] = {
                                "ip": addr[0], "port": addr[1],
                            }
            except Exception:
                continue

    udp_thread = threading.Thread(target=udp_listener, daemon=True)
    udp_thread.start()

    # --- TCP listener ---
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("0.0.0.0", port))
    tcp_sock.listen(16)

    print(f"Relay server listening on :{port} (TCP + UDP)")

    def handle_client(conn, addr):
        try:
            msg = relay_recv_msg(conn)
            mtype = msg["type"]
            sid = msg["session"]

            if mtype == "register":
                # Sender registering a new session
                with sessions_lock:
                    sessions[sid] = {
                        "sender": conn,
                        "receiver": None,
                        "sender_udp": None,
                        "receiver_udp": None,
                        "event": threading.Event(),
                    }
                    sess = sessions[sid]
                print(f"[{sid}] Sender registered from {addr[0]}:{addr[1]}")
                relay_send_msg(conn, {"type": "waiting"})

                # Wait for receiver to join (timeout 5 minutes)
                if not sess["event"].wait(timeout=300):
                    relay_send_msg(conn, {"type": "error", "msg": "Timeout waiting for receiver"})
                    with sessions_lock:
                        sessions.pop(sid, None)
                    conn.close()
                    return

                # Both peers connected — wait a moment for UDP discovery
                time.sleep(1)

                # Send peer info to both sides
                with sessions_lock:
                    sender_udp = sess.get("sender_udp")
                    receiver_udp = sess.get("receiver_udp")

                relay_send_msg(conn, {
                    "type": "ready",
                    "peer_udp": receiver_udp,
                })
                relay_send_msg(sess["receiver"], {
                    "type": "ready",
                    "peer_udp": sender_udp,
                })
                print(f"[{sid}] Peer info exchanged: sender_udp={sender_udp}, receiver_udp={receiver_udp}")

                # Wait for punch results from both sides
                sender_result = relay_recv_msg(conn)
                receiver_result = relay_recv_msg(sess["receiver"])

                sender_ok = sender_result.get("success", False)
                receiver_ok = receiver_result.get("success", False)
                direct = sender_ok and receiver_ok

                mode = "direct" if direct else "relay"
                print(f"[{sid}] Punch results: sender={sender_ok}, receiver={receiver_ok} -> {mode}")

                relay_send_msg(conn, {"type": "mode", "mode": mode})
                relay_send_msg(sess["receiver"], {"type": "mode", "mode": mode})

                if mode == "relay":
                    # Bridge TCP between sender and receiver
                    print(f"[{sid}] Starting TCP relay bridge")
                    recv_conn = sess["receiver"]
                    _relay_bridge(conn, recv_conn, sid)
                else:
                    print(f"[{sid}] Direct RUDP transfer, relay done")

                # Cleanup
                with sessions_lock:
                    sessions.pop(sid, None)

            elif mtype == "join":
                # Receiver joining an existing session
                with sessions_lock:
                    sess = sessions.get(sid)
                if sess is None:
                    relay_send_msg(conn, {"type": "error", "msg": "Unknown session"})
                    conn.close()
                    return
                print(f"[{sid}] Receiver joined from {addr[0]}:{addr[1]}")
                sess["receiver"] = conn
                sess["event"].set()
                # The sender's handler thread drives the rest of the protocol
                # This thread just waits for the session to end
                while True:
                    with sessions_lock:
                        if sid not in sessions:
                            break
                    time.sleep(1)
            else:
                relay_send_msg(conn, {"type": "error", "msg": f"Unknown message type: {mtype}"})
                conn.close()

        except (ConnectionError, json.JSONDecodeError, KeyError) as e:
            print(f"[relay] Client {addr} error: {e}")
            conn.close()

    def _relay_bridge(sock_a, sock_b, sid):
        """Forward bytes between two TCP sockets until one side closes."""
        def forward(src, dst, label):
            try:
                while True:
                    data = src.recv(CHUNK)
                    if not data:
                        break
                    dst.sendall(data)
            except (ConnectionError, OSError):
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        t1 = threading.Thread(target=forward, args=(sock_a, sock_b, "A->B"), daemon=True)
        t2 = threading.Thread(target=forward, args=(sock_b, sock_a, "B->A"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print(f"[{sid}] Relay bridge closed")
        try:
            sock_a.close()
        except OSError:
            pass
        try:
            sock_b.close()
        except OSError:
            pass

    try:
        while True:
            conn, addr = tcp_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nRelay server shutting down.")
    finally:
        tcp_sock.close()
        udp_sock.close()


# ---------------------------------------------------------------------------
# Send command
# ---------------------------------------------------------------------------

def _prepare_send(path):
    """Prepare a file or directory for sending.  Returns (data_path, metadata, tmp_archive)."""
    is_dir = os.path.isdir(path)
    name = os.path.basename(path.rstrip(os.sep))
    tmp_archive = None

    if is_dir:
        print(f"Packing directory: {name}/")
        tmp_archive = tar_directory(path)
        data_path = tmp_archive
    else:
        data_path = path

    data_size = os.path.getsize(data_path)
    print("Computing checksum...")
    file_hash = sha256_file(data_path)

    metadata = {
        "name": name,
        "size": data_size,
        "type": "directory" if is_dir else "file",
        "sha256": file_hash,
    }
    return data_path, metadata, tmp_archive


def cmd_send(args):
    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"Error: '{path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    data_path, metadata, tmp_archive = _prepare_send(path)

    if args.relay:
        # --- Relay mode ---
        try:
            _send_relay(args, data_path, metadata)
        finally:
            if tmp_archive:
                os.unlink(tmp_archive)
        return

    # --- Direct LAN mode (original behavior) ---
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_port = args.port if hasattr(args, "port") and args.port else 0
    server.bind(("0.0.0.0", bind_port))
    server.listen(1)
    port = server.getsockname()[1]

    ip = args.ip if (hasattr(args, "ip") and args.ip) else get_local_ip()
    code = encode_addr(ip, port)

    name = metadata["name"]
    is_dir = metadata["type"] == "directory"
    print()
    print(f"  Name : {name}{'/' if is_dir else ''}")
    print(f"  Size : {fmt_size(metadata['size'])}")
    print(f"  Code : {code}")
    print()
    print("Waiting for receiver... (Ctrl+C to cancel)")

    try:
        conn, addr = server.accept()
        print(f"Receiver connected from {addr[0]}:{addr[1]}")
        tcp_send_file(conn, data_path, metadata)
        print(f"Transfer complete.  SHA-256: {metadata['sha256'][:16]}...")
        conn.close()
    except KeyboardInterrupt:
        print("\nCancelled.")
    finally:
        server.close()
        if tmp_archive:
            os.unlink(tmp_archive)


def _send_relay(args, data_path, metadata):
    """Send a file via relay server with NAT punchthrough."""
    relay_host, relay_port = _parse_relay_addr(args.relay)

    # Generate session ID
    W = len(WORDS)
    session_id = secrets.randbelow(W ** 5)
    code = words_encode(session_id)

    name = metadata["name"]
    is_dir = metadata["type"] == "directory"
    print()
    print(f"  Name  : {name}{'/' if is_dir else ''}")
    print(f"  Size  : {fmt_size(metadata['size'])}")
    print(f"  Relay : {args.relay}")
    print(f"  Code  : {code}")
    print()

    # Connect to relay TCP
    relay_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_tcp.settimeout(10)
    relay_tcp.connect((relay_host, relay_port))
    relay_tcp.settimeout(None)

    relay_send_msg(relay_tcp, {"type": "register", "session": session_id})
    resp = relay_recv_msg(relay_tcp)
    if resp.get("type") == "error":
        print(f"Error from relay: {resp.get('msg')}", file=sys.stderr)
        sys.exit(1)
    print("Waiting for receiver... (Ctrl+C to cancel)")

    # Set up UDP socket for discovery
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", 0))

    # Discover our public UDP mapping (in background while waiting for receiver)
    our_udp = None
    def do_discover():
        nonlocal our_udp
        try:
            discover_msg = json.dumps({
                "type": "discover",
                "session": session_id,
                "role": "sender",
            }).encode("utf-8")
            for _ in range(5):
                udp_sock.sendto(discover_msg, (relay_host, relay_port))
                ready, _, _ = select.select([udp_sock], [], [], 2.0)
                if ready:
                    data, _ = udp_sock.recvfrom(1024)
                    resp = json.loads(data.decode("utf-8"))
                    if resp.get("type") == "mapped":
                        our_udp = {"ip": resp["ip"], "port": resp["port"]}
                        return
        except Exception:
            pass

    discover_thread = threading.Thread(target=do_discover, daemon=True)
    discover_thread.start()

    # Wait for the "ready" message (relay sends after receiver joins + discovery)
    ready_msg = relay_recv_msg(relay_tcp)
    if ready_msg.get("type") == "error":
        print(f"Error: {ready_msg.get('msg')}", file=sys.stderr)
        sys.exit(1)

    discover_thread.join(timeout=5)

    peer_udp = ready_msg.get("peer_udp")

    # Attempt UDP hole punch
    punch_ok = False
    if peer_udp and our_udp:
        print(f"Attempting UDP hole punch to {peer_udp['ip']}:{peer_udp['port']}...")
        try:
            punch_ok = udp_punch(udp_sock, peer_udp, session_id, timeout=5)
        except Exception:
            punch_ok = False

    # Report result
    relay_send_msg(relay_tcp, {"type": "punch_result", "success": punch_ok})

    # Get mode decision from relay
    mode_msg = relay_recv_msg(relay_tcp)
    mode = mode_msg.get("mode", "relay")

    if mode == "direct":
        print(f"Hole punch successful! Transferring directly via RUDP...")
        rudp_send_file(udp_sock, (peer_udp["ip"], peer_udp["port"]), data_path, metadata)
        print(f"Transfer complete.  SHA-256: {metadata['sha256'][:16]}...")
    else:
        print(f"Falling back to relay transfer...")
        tcp_send_file(relay_tcp, data_path, metadata)
        print(f"Transfer complete.  SHA-256: {metadata['sha256'][:16]}...")

    relay_tcp.close()
    udp_sock.close()


# ---------------------------------------------------------------------------
# Receive command
# ---------------------------------------------------------------------------

def cmd_receive(args):
    code = " ".join(args.code)
    output_dir = args.output

    if args.relay:
        _receive_relay(args, code, output_dir)
        return

    # --- Direct LAN mode (original behavior) ---
    try:
        ip, port = decode_addr(code)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {ip}:{port}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))
        sock.settimeout(None)
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        print(f"Error: Could not connect — {e}", file=sys.stderr)
        sys.exit(1)

    try:
        tcp_recv_file(sock, output_dir)
    except KeyboardInterrupt:
        print("\nCancelled.")
    finally:
        sock.close()


def _receive_relay(args, code, output_dir):
    """Receive a file via relay server with NAT punchthrough."""
    relay_host, relay_port = _parse_relay_addr(args.relay)

    try:
        session_id = words_decode(code)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Joining session via relay {args.relay}...")

    # Connect to relay TCP
    relay_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_tcp.settimeout(10)
    relay_tcp.connect((relay_host, relay_port))
    relay_tcp.settimeout(None)

    relay_send_msg(relay_tcp, {"type": "join", "session": session_id})

    # Set up UDP socket for discovery
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", 0))

    # Discover our public UDP mapping
    our_udp = None
    discover_msg = json.dumps({
        "type": "discover",
        "session": session_id,
        "role": "receiver",
    }).encode("utf-8")
    for _ in range(5):
        udp_sock.sendto(discover_msg, (relay_host, relay_port))
        ready, _, _ = select.select([udp_sock], [], [], 2.0)
        if ready:
            data, _ = udp_sock.recvfrom(1024)
            resp = json.loads(data.decode("utf-8"))
            if resp.get("type") == "mapped":
                our_udp = {"ip": resp["ip"], "port": resp["port"]}
                break

    # Wait for "ready" from relay
    ready_msg = relay_recv_msg(relay_tcp)
    if ready_msg.get("type") == "error":
        print(f"Error: {ready_msg.get('msg')}", file=sys.stderr)
        sys.exit(1)

    peer_udp = ready_msg.get("peer_udp")

    # Attempt UDP hole punch
    punch_ok = False
    if peer_udp and our_udp:
        print(f"Attempting UDP hole punch to {peer_udp['ip']}:{peer_udp['port']}...")
        try:
            punch_ok = udp_punch(udp_sock, peer_udp, session_id, timeout=5)
        except Exception:
            punch_ok = False

    # Report result
    relay_send_msg(relay_tcp, {"type": "punch_result", "success": punch_ok})

    # Get mode decision
    mode_msg = relay_recv_msg(relay_tcp)
    mode = mode_msg.get("mode", "relay")

    try:
        if mode == "direct":
            print(f"Hole punch successful! Receiving directly via RUDP...")
            rudp_recv_file(udp_sock, peer_udp, output_dir)
        else:
            print(f"Receiving via relay...")
            tcp_recv_file(relay_tcp, output_dir)
    except KeyboardInterrupt:
        print("\nCancelled.")
    finally:
        relay_tcp.close()
        udp_sock.close()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _parse_relay_addr(addr_str):
    """Parse 'host:port' string into (host, port)."""
    if ":" not in addr_str:
        raise ValueError(f"Relay address must be host:port, got '{addr_str}'")
    host, port_str = addr_str.rsplit(":", 1)
    return host, int(port_str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="filedropper",
        description="Peer-to-peer file sharing with five-word codes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s send photo.jpg
  %(prog)s send ./my-project/
  %(prog)s receive alpha-bravo-charlie-delta-echo
  %(prog)s receive alpha bravo charlie delta echo
  %(prog)s receive alpha-bravo-charlie-delta-echo -o ~/Downloads

relay mode (NAT punchthrough):
  %(prog)s relay -p 9999
  %(prog)s send --relay myserver:9999 photo.jpg
  %(prog)s receive --relay myserver:9999 alpha-bravo-charlie-delta-echo

notes:
  Without --relay, both sender and receiver must be on the same local
  network, or the sender must have a publicly reachable IP (use --ip
  and --port for port-forwarding scenarios).

  With --relay, transfers work across NATs.  A relay server must be
  running on a publicly reachable host.  The tool will attempt UDP
  hole punching for direct transfer, falling back to TCP relay.""",
    )
    sub = parser.add_subparsers(dest="command")

    sp_send = sub.add_parser("send", help="Send a file or directory")
    sp_send.add_argument("path", help="File or directory to send")
    sp_send.add_argument(
        "-p", "--port", type=int, default=0,
        help="Port to listen on (default: random)",
    )
    sp_send.add_argument(
        "--ip", default=None,
        help="Override the IP encoded in the code (for port-forwarding / WAN)",
    )
    sp_send.add_argument(
        "--relay", default=None,
        help="Relay server address (host:port) for NAT punchthrough",
    )

    sp_recv = sub.add_parser("receive", help="Receive a file or directory")
    sp_recv.add_argument(
        "code", nargs="+",
        help="Five-word code (space or dash separated)",
    )
    sp_recv.add_argument(
        "-o", "--output", default=".",
        help="Output directory (default: current directory)",
    )
    sp_recv.add_argument(
        "--relay", default=None,
        help="Relay server address (host:port) for NAT punchthrough",
    )

    sp_relay = sub.add_parser("relay", help="Run a relay/rendezvous server")
    sp_relay.add_argument(
        "-p", "--port", type=int, default=9999,
        help="Port to listen on for TCP and UDP (default: 9999)",
    )

    args = parser.parse_args()

    if args.command == "send":
        cmd_send(args)
    elif args.command == "receive":
        cmd_receive(args)
    elif args.command == "relay":
        cmd_relay(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
