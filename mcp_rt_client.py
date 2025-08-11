import asyncio, struct, json, time, hmac, hashlib, secrets, contextlib

HOST, PORT = "127.0.0.1", 5055
CLIENT_VERSION = "1.0"
FEATURES = ["json", "hmac", "stream", "resume"]
TOKEN_ID = "demo"
TOKEN_SECRET = b"super-secret-demo-token"

PING_INTERVAL = 10           # seconds
PONG_TIMEOUT = 5             # seconds
RECONNECT_BACKOFF = (1, 2, 4, 8, 10)  # seconds
OUTBOUND_MAXSIZE = 1000
REQUEST_TIMEOUT = 5

TOPIC = "game.state"
MATCH_ID = "ABC123"

def pack_frame(obj: dict) -> bytes:
    b = json.dumps(obj, separators=(",", ":")).encode()
    return struct.pack(">I", len(b)) + b

async def read_frame(reader: asyncio.StreamReader) -> dict:
    hdr = await reader.readexactly(4)
    (ln,) = struct.unpack(">I", hdr)
    body = await reader.readexactly(ln)
    return json.loads(body.decode())

def hmac_hex(secret: bytes, message: str) -> str:
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()

class MCPRealtimeClient:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.reader = None
        self.writer = None
        self.out_q = asyncio.Queue(maxsize=OUTBOUND_MAXSIZE)
        self.tasks = []
        self.session_id = None
        self.last_seq = 0
        self._pongs = asyncio.Queue()
        self._connected = asyncio.Event()
        self._stop = asyncio.Event()

    async def connect_loop(self):
        """Main loop: connect → handshake → auth → run → on error reconnect."""
        while not self._stop.is_set():
            for delay in RECONNECT_BACKOFF:
                try:
                    await self._connect_once()
                    await self._run_until_disconnect()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    print(f"[conn] error: {e}")
                if self._stop.is_set(): return
                print(f"[conn] reconnect in {delay}s")
                await asyncio.sleep(delay)
            # after full backoff cycle, keep trying with max delay
            await asyncio.sleep(RECONNECT_BACKOFF[-1])

    async def _connect_once(self):
        print(f"[conn] connecting to {self.host}:{self.port}")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self._handshake_and_auth()
        # resubscribe/resume
        if self.last_seq > 0:
            await self.send_now({"type":"RESUME","topic":TOPIC,"since":self.last_seq})
        else:
            await self.send_now({"type":"SUBSCRIBE","topic":TOPIC,"filters":{"matchId":MATCH_ID}})
        self._connected.set()
        print("[conn] ready")

    async def _handshake_and_auth(self):
        await self.send_now({"type":"HELLO","version":CLIENT_VERSION,"features":FEATURES})
        sh = await read_frame(self.reader)
        assert sh.get("type") == "SERVER_HELLO", f"bad handshake: {sh}"
        nonce = sh["nonce"]
        sig = hmac_hex(TOKEN_SECRET, nonce)
        await self.send_now({"type":"AUTH","tokenId":TOKEN_ID,"signature":sig})
        auth = await read_frame(self.reader)
        if auth.get("type") != "AUTH_OK":
            raise RuntimeError(f"auth failed: {auth}")
        self.session_id = auth["sessionId"]

    async def _run_until_disconnect(self):
        # spawn reader, writer, heartbeat
        self.tasks = [
            asyncio.create_task(self.reader_task()),
            asyncio.create_task(self.writer_task()),
            asyncio.create_task(self.heartbeat_task()),
        ]
        done, pending = await asyncio.wait(self.tasks, return_when=asyncio.FIRST_EXCEPTION)
        # any exception -> tear down
        for t in self.tasks:
            t.cancel()
        with contextlib.suppress(Exception):
            for t in self.tasks:
                await t
        self.tasks.clear()
        self._connected.clear()
        self._drain_writer()

    def _drain_writer(self):
        try:
            if self.writer:
                self.writer.close()
        except Exception:
            pass

    async def reader_task(self):
        while True:
            msg = await read_frame(self.reader)
            t = msg.get("type")
            if t == "PONG":
                await self._pongs.put(msg)
            elif t == "EVENT" and msg.get("topic") == TOPIC:
                seq = msg.get("seq", 0)
                if seq <= self.last_seq:
                    # duplicate or out-of-order older; skip
                    continue
                self.last_seq = seq
                await self.on_game_event(msg["data"], seq)
            elif t == "SNAPSHOT" and msg.get("topic") == TOPIC:
                # full state replace then deltas will follow
                await self.on_snapshot(msg["data"])
            elif t == "ERROR":
                print("[server-error]", msg.get("reason"))
            else:
                # other app messages (acks, etc.)
                pass

    async def writer_task(self):
        while True:
            obj = await self.out_q.get()
            self.writer.write(pack_frame(obj))
            await self.writer.drain()

    async def heartbeat_task(self):
        while True:
            await asyncio.sleep(PING_INTERVAL)
            await self.send_now({"type":"PING","ts":time.time()})
            try:
                await asyncio.wait_for(self._pongs.get(), timeout=PONG_TIMEOUT)
            except asyncio.TimeoutError:
                raise RuntimeError("heartbeat timeout")

    async def send(self, obj: dict, *, timeout=REQUEST_TIMEOUT):
        """Queue a message; drop on full queue (or implement backpressure)."""
        try:
            await asyncio.wait_for(self.out_q.put(obj), timeout=timeout)
        except asyncio.TimeoutError:
            print("[warn] outbound queue full; dropping:", obj.get("type"))

    async def send_now(self, obj: dict):
        """Bypass queue for handshake/critical steps."""
        self.writer.write(pack_frame(obj))
        await self.writer.drain()

    # ---------- app-level handlers ----------
    async def on_snapshot(self, state: dict):
        print(f"[state] SNAPSHOT received: {state}")

    async def on_game_event(self, delta: dict, seq: int):
        # apply delta to local model (simple print here)
        print(f"[state] DELTA seq={seq}: {delta}")

    # ---------- lifecycle ----------
    async def start(self):
        await self.connect_loop()

    async def stop(self):
        self._stop.set()
        for t in self.tasks: t.cancel()
        self._drain_writer()

if __name__ == "__main__":
    try:
        asyncio.run(MCPRealtimeClient(HOST, PORT).start())
    except KeyboardInterrupt:
        pass
