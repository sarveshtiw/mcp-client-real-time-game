import asyncio, json, struct, secrets, time, hmac, hashlib, collections

HOST, PORT = "127.0.0.1", 5055

# Demo token DB (tokenId -> secret)
TOKENS = {"demo": "super-secret-demo-token"}

# --- framing helpers (length-prefixed JSON) ---
def pack(obj: dict) -> bytes:
    b = json.dumps(obj, separators=(",", ":")).encode()
    return struct.pack(">I", len(b)) + b

async def read_frame(reader: asyncio.StreamReader) -> dict:
    hdr = await reader.readexactly(4)
    (ln,) = struct.unpack(">I", hdr)
    body = await reader.readexactly(ln)
    return json.loads(body.decode())

def hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

# --- in-memory game state + event bus ---
class GameBus:
    def __init__(self, buffer_size=1024):
        self.seq = 0
        self.state = {"matchId": "ABC123", "score": {"A": 0, "B": 0}, "clock": 0}
        self.buffer = collections.deque(maxlen=buffer_size)  # (seq, event)
        self.subscribers = set()  # set of (writer, matchId)

    def snapshot(self):
        return dict(self.state)

    def append_event(self, data: dict):
        self.seq += 1
        evt = {"type": "EVENT", "topic": "game.state", "seq": self.seq, "data": data}
        self.buffer.append((self.seq, evt))
        return evt

    def since(self, seq_from: int):
        return [evt for s, evt in self.buffer if s > seq_from]

    async def broadcast(self, evt: dict, match_id="ABC123"):
        dead = []
        for (w, mid) in self.subscribers:
            if mid != match_id:
                continue
            try:
                w.write(pack(evt))
                await w.drain()
            except Exception:
                dead.append((w, mid))
        for d in dead:
            self.subscribers.discard(d)

BUS = GameBus()

async def game_tick():
    """Toy game loop: advance clock, randomly increment a team score."""
    import random
    while True:
        await asyncio.sleep(2)
        # advance clock
        BUS.state["clock"] += 2
        # sometimes score
        if random.random() < 0.5:
            team = "A" if random.random() < 0.5 else "B"
            BUS.state["score"][team] += 1
            delta = {"matchId": "ABC123", "clock": BUS.state["clock"], "score": BUS.state["score"]}
        else:
            delta = {"matchId": "ABC123", "clock": BUS.state["clock"]}
        evt = BUS.append_event(delta)
        await BUS.broadcast(evt)

# --- per-connection handler ---
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    session_id = None
    match_filter = None
    nonce = None

    async def send(obj):  # small helper
        writer.write(pack(obj))
        await writer.drain()

    try:
        # 1) HELLO
        hello = await read_frame(reader)
        if hello.get("type") != "HELLO":
            await send({"type": "ERROR", "reason": "expected HELLO"}); return
        nonce = secrets.token_hex(16)
        await send({"type": "SERVER_HELLO", "acceptVersion": "1.0", "nonce": nonce})

        # 2) AUTH (HMAC over nonce)
        auth = await read_frame(reader)
        if auth.get("type") != "AUTH":
            await send({"type": "AUTH_FAIL", "reason": "expected AUTH"}); return
        token_id, sig = auth.get("tokenId"), auth.get("signature")
        secret = TOKENS.get(token_id)
        if not secret or sig != hmac_hex(secret, nonce):
            await send({"type": "AUTH_FAIL", "reason": "invalid token/signature"}); return
        session_id = secrets.token_hex(8)
        await send({"type": "AUTH_OK", "sessionId": session_id})

        # 3) main loop
        while True:
            msg = await read_frame(reader)
            t = msg.get("type")

            if t == "PING":
                await send({"type": "PONG", "ts": time.time()})

            elif t == "SUBSCRIBE":
                filt = msg.get("filters", {})
                match_filter = filt.get("matchId", "ABC123")
                BUS.subscribers.add((writer, match_filter))
                # send snapshot immediately
                snap = {"type": "SNAPSHOT", "topic": "game.state", "data": BUS.snapshot()}
                await send(snap)
                # also send last few events to warm up
                for _, evt in list(BUS.buffer)[-10:]:
                    await send(evt)

            elif t == "RESUME":
                since = int(msg.get("since", 0))
                # send missed events if available
                missing = BUS.since(since)
                if not missing:
                    # fallback: send snapshot to ensure consistency
                    await send({"type": "SNAPSHOT", "topic": "game.state", "data": BUS.snapshot()})
                for evt in missing:
                    await send(evt)

            elif t == "ECHO":
                await send({"type": "ECHO_OK", "echo": msg.get("body")})

            else:
                await send({"type": "ERROR", "reason": f"unknown type {t}"})

    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        # print(f"[server] error with {addr}: {e}")
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        # remove from subscribers
        for pair in list(BUS.subscribers):
            if pair[0] is writer:
                BUS.subscribers.discard(pair)

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Mock MCP game server on {HOST}:{PORT}")
    async with server:
        await asyncio.gather(server.serve_forever(), game_tick())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
