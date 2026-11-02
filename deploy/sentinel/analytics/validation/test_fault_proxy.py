"""Fault proxy behaviour: only an established tunnel's response is dropped, once."""

import asyncio
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fault_proxy  # noqa: E402


class FaultProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.directory.name, "proxy.jsonl")
        self.proxy = fault_proxy.Proxy("127.0.0.1", 2048, self.log)

        self.received = 0

        async def upstream(reader, writer):
            # Answer every client write, like a TLS handshake and an HTTP response.
            while data := await reader.read(65536):
                self.received += len(data)
                writer.write(b"reply:%d" % len(data))
                await writer.drain()
            writer.close()

        self.upstream = await asyncio.start_server(upstream, "127.0.0.1", 0)
        self.server = await asyncio.start_server(self.proxy.handle, "127.0.0.1", 0)
        self.upstream_port = self.upstream.sockets[0].getsockname()[1]
        self.proxy_port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        for server in (self.server, self.upstream):
            server.close()
        # Let tunnel handlers record their close before the log goes away.
        await asyncio.sleep(0.2)
        self.proxy.log.close()
        self.directory.cleanup()

    async def tunnel(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n" % self.upstream_port)
        await writer.drain()
        return reader, writer, await reader.readuntil(b"\r\n\r\n")

    async def exchange(self, reader, writer, size):
        writer.write(b"x" * size)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(65536), 0.5)
        except asyncio.TimeoutError:
            return None

    async def test_drops_one_response_on_an_established_tunnel(self):
        reader, writer, status = await self.tunnel()
        self.assertIn(b"200", status)
        self.proxy.set_mode("drop-next")
        # A new tunnel's first response (the handshake) is never dropped.
        self.assertEqual(b"reply:300", await self.exchange(reader, writer, 300))
        # Too small to be an upload: forwarded.
        self.assertEqual(b"reply:100", await self.exchange(reader, writer, 100))
        # An upload reaches the server but its response never reaches the client.
        self.assertIsNone(await self.exchange(reader, writer, 3000))
        self.assertEqual("pass", self.proxy.mode)
        self.assertEqual(1, self.proxy.poisoned)
        # The ambiguous tunnel stays hung; a new tunnel works normally.
        other_reader, other_writer, _ = await self.tunnel()
        self.assertEqual(b"reply:3000", await self.exchange(other_reader, other_writer, 3000))
        for stream in (writer, other_writer):
            stream.close()
        events = [json.loads(line)["event"] for line in open(self.log, encoding="utf-8")]
        self.assertEqual(1, events.count("response-dropped"))

    async def test_mid_upload_downstream_data_does_not_defeat_the_injection(self):
        reader, writer, _ = await self.tunnel()
        self.assertEqual(b"reply:300", await self.exchange(reader, writer, 300))
        self.proxy.set_mode("drop-next")
        # Downstream data in the middle of an upload (a TLS ticket, an HTTP/2 window
        # update) is forwarded and does not restart the request count...
        self.assertEqual(b"reply:1500", await self.exchange(reader, writer, 1500))
        # ...so the response once the upload passes --request-bytes is dropped.
        self.assertIsNone(await self.exchange(reader, writer, 1500))
        self.assertEqual(1, self.proxy.poisoned)
        writer.close()

    async def test_the_whole_upload_reaches_the_server_after_its_response_is_dropped(self):
        reader, writer, _ = await self.tunnel()
        self.assertEqual(b"reply:300", await self.exchange(reader, writer, 300))
        self.proxy.set_mode("drop-next")
        # The server answers part-way through the upload, above --request-bytes: that
        # answer is dropped, and the rest of the upload must still be forwarded.
        self.assertIsNone(await self.exchange(reader, writer, 3000))
        self.assertIsNone(await self.exchange(reader, writer, 1300))
        await asyncio.sleep(0.2)
        self.assertEqual(300 + 3000 + 1300, self.received)
        self.assertEqual(1, self.proxy.poisoned)
        writer.close()

    async def test_drop_then_outage_refuses_new_tunnels(self):
        reader, writer, _ = await self.tunnel()
        self.assertEqual(b"reply:300", await self.exchange(reader, writer, 300))
        self.proxy.set_mode("drop-next-then-outage")
        self.assertIsNone(await self.exchange(reader, writer, 4000))
        self.assertEqual("outage", self.proxy.mode)
        _, refused, status = await self.tunnel()
        self.assertIn(b"503", status)
        refused.close()
        self.proxy.set_mode("pass")
        other_reader, other_writer, status = await self.tunnel()
        self.assertIn(b"200", status)
        self.assertEqual(b"reply:10", await self.exchange(other_reader, other_writer, 10))
        writer.close()
        other_writer.close()


if __name__ == "__main__":
    unittest.main()
