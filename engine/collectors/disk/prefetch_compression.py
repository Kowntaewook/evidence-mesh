"""Bounded MAM4 decoding using Dissect's XPRESS-Huffman tree/bit primitives."""

import io
import struct

from engine.ingestion.evidence import ArtifactError, DependencyUnavailable

MAX_PREFETCH_BYTES = 16 * 1024 * 1024


def decompress_mam(data: bytes) -> bytes:
    if len(data) < 8 or data[:3] != b"MAM":
        raise ArtifactError("Truncated MAM Prefetch header")
    if data[3] != 4:
        raise DependencyUnavailable(f"MAM variant 0x{data[3]:02x} is not supported; MAM4 is supported")
    size = struct.unpack_from("<I", data, 4)[0]
    if not 152 <= size <= MAX_PREFETCH_BYTES or len(data) > MAX_PREFETCH_BYTES:
        raise ArtifactError("MAM input/output exceeds the 16 MiB Prefetch bound or is invalid")
    try:
        from dissect.util.compression.lzxpress_huffman import BitString, _build_tree
    except ImportError as exc:
        raise DependencyUnavailable("MAM4 requires dissect.util XPRESS-Huffman support") from exc
    source = io.BytesIO(data[8:])

    class BoundedBits(BitString):
        # The upstream decoder pads at EOF. Track actual buffered bits so a
        # truncated stream cannot synthesize trailing zero-valued literals.
        def word(self):
            raw = self.source.read(2)
            if len(raw) == 1:
                raise ArtifactError("Truncated MAM bit word")
            self.available += len(raw) * 8
            return int.from_bytes(raw, "little")

        def init(self, stream):
            self.source, self.available = stream, 0
            self.mask = (self.word() << 16) + self.word()
            self.bits = 32

        def skip(self, count):
            if count > self.available:
                raise ArtifactError("Truncated MAM compressed bits")
            self.available -= count
            self.mask = (self.mask << count) & 0xFFFFFFFF
            self.bits -= count
            if self.bits < 16:
                self.mask += self.word() << (16 - self.bits)
                self.bits += 16

    result = bytearray()
    try:
        while len(result) < size:
            tree = _build_tree(source.read(256))
            bits = BoundedBits()
            bits.init(source)
            block_end = min(size, len(result) + 65536)
            while len(result) < block_end:
                if source.tell() > len(data) - 8:
                    raise ArtifactError("Truncated MAM compressed stream")
                symbol = bits.decode(tree)
                if symbol < 256:
                    result.append(symbol)
                    continue
                encoded = symbol - 256
                distance_bits = encoded >> 4
                distance = (1 << distance_bits) + bits.lookup(distance_bits)
                count = encoded & 15
                if count == 15:
                    count += struct.unpack("<B", bits.read(1))[0]
                    if count == 270:
                        count = struct.unpack("<H", bits.read(2))[0]
                bits.skip(distance_bits)
                count += 3
                if distance > len(result) or len(result) + count > size:
                    raise ArtifactError("MAM match leaves the declared output bounds")
                # Copy overlapping matches in chunks without allocating unbounded output.
                while count:
                    take = min(count, distance)
                    start = len(result) - distance
                    result.extend(result[start : start + take])
                    count -= take
    except (ValueError, IndexError, AttributeError, struct.error, TypeError) as exc:
        raise ArtifactError(f"Invalid MAM4 compressed data: {exc}") from exc
    if len(result) != size or result[4:8] != b"SCCA":
        raise ArtifactError("MAM output is not a complete SCCA Prefetch")
    return bytes(result)
