"""
Glomar - Deniable storage system.

Takes a set of streams (aka files), encrypts them, and scatters them around a
set of slots.

To decrypt, you search through the slots looking for blocks that have a valid
MAC and combine all the data from those into a single stream.
"""

import hmac
import secrets
import struct
from chacha20 import ChaCha20
from hashlib import sha256

# Size of the MAC
MAC_SIZE = 32
# Key Size for the stream cipher
KEY_SIZE = 32
# Nonce size
NONCE_SIZE = 8
# Size of the meta data we include in each encrypted block
BLOCK_HEADER_SIZE = 8
# Actual size of each block
KB = 1024
BLOCK_SIZE = 4 * KB
BLOCK_DATA_SIZE = BLOCK_SIZE - MAC_SIZE
USABLE_SIZE = BLOCK_DATA_SIZE - BLOCK_HEADER_SIZE


# Modern Fisher-Yates
# Double check this isn't broken
def shuffle(items):
    res = items.copy()
    n = len(res)
    for i in range(0, n - 1):
        j = i + secrets.randbelow(n - i)
        res[j], res[i] = res[i], res[j]

    return res


# https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class InvalidSize(Exception):
    pass


class WeirdState(Exception):
    pass


class Block:
    def __init__(self, idx, data):
        self._data = data
        self._idx = idx

    def idx(self):
        return self._idx

    def __bytes__(self):
        assert len(self._data) == BLOCK_SIZE
        return self._data


class RandomBlock(Block):
    def __init__(self, idx):
        super().__init__(idx, secrets.token_bytes(BLOCK_SIZE))


def hmac_block(key, idx, data):
    h = hmac.new(key, digestmod=sha256)
    h.update(struct.pack('>Q', idx))
    h.update(data)
    return h.digest()


class MACBlock(Block):
    def __init__(self, idx, data, key):
        if len(data) != BLOCK_DATA_SIZE:
            raise InvalidSize()
        self._body = data
        self._mac = hmac_block(key, idx, data)
        super().__init__(idx, self._body + self._mac)


class NonceBlock(MACBlock):
    def __init__(self, idx, key, data=None):
        body = data
        if data is None:
            body = secrets.token_bytes(BLOCK_DATA_SIZE)

        super().__init__(idx, body, key)

    def get_nonce(self):
        return sha256(self._body).digest()[:NONCE_SIZE]


def macblock_to_data(block):
    return bytes(block)[:BLOCK_DATA_SIZE]


def block_to_nonceblock(block, key):
    return NonceBlock(block.idx(), key, data=macblock_to_data(block))


def derive_keys(base_key):
    """
    Generate:
        * A HMAC key for finding the nonce block
        * A HMAC key for finding the stream blocks
        * A key to decrypt the stream blocks

    Not the best KDF, should be replaced with something better.

    We are limited by the fact we can't store data like salts.
    """
    hmac_key_nonce = hmac.digest(base_key, b'HMAC_NONCE_KEY', sha256)
    hmac_key_stream = hmac.digest(base_key, b'HMAC_STREAM_KEY', sha256)
    stream_key = \
        hmac.digest(base_key, b'CHACHA20_STREAM_KEY', sha256)[:KEY_SIZE]

    return (hmac_key_nonce, hmac_key_stream, stream_key)


def pad(data, length):
    """
    Simple random padding
    """
    assert len(data) <= length
    return data + secrets.token_bytes(length - len(data))


def add_header_to_block(data):
    """
    Adds the header struct to the block.
    """
    if len(data) > USABLE_SIZE:
        raise InvalidSize()
    return pad(struct.pack('>Q', len(data)) + data, BLOCK_DATA_SIZE)


def remove_header(data):
    dlen = struct.unpack('>Q', data[:8])[0]
    return data[8:8 + dlen]


def validate_block(key, block):
    """
    Check if a block can be decrypted with the key
    """
    assert isinstance(block, Block)
    brep = bytes(block)
    data = brep[:BLOCK_DATA_SIZE]
    mac = brep[BLOCK_DATA_SIZE:]
    assert len(mac) == MAC_SIZE

    digest = hmac_block(key, block.idx(), data)
    return hmac.compare_digest(digest, mac)


class CreateGlomarStore:

    def __init__(self, n_blocks, ratio_start=0.1):
        self._n_blocks = n_blocks
        self._streams = []
        # Shuffle it once
        self._locations = shuffle(list(range(n_blocks)))

    def add(self, key, data):
        """
        Add data to the store
        """
        res = []
        all_chunks = list(chunks(data, USABLE_SIZE))
        # +1 for the Nonce block
        positions = sorted(self._locations[:len(all_chunks) + 1])
        self._locations = self._locations[len(all_chunks) + 1:]

        # Derivive several keys from the base key
        nonce_hmac_key, hmac_key, stream_key = derive_keys(key)

        # Get the Nonce block
        stream_nonce_block = NonceBlock(positions[0], nonce_hmac_key)
        stream_nonce = stream_nonce_block.get_nonce()

        c = ChaCha20(key=stream_key, nonce=stream_nonce, counter=0)

        res.append((positions[0], stream_nonce_block))

        for idx, chunk in enumerate(all_chunks):
            nidx = idx + 1
            loc = positions[nidx]
            block = add_header_to_block(chunk)
            encrypted = c.encrypt(block)
            res.append((loc, MACBlock(loc, encrypted, hmac_key)))

        self._streams.append(res)

    def pack(self):
        res = [None for _ in range(self._n_blocks)]
        for stream in self._streams:
            for idx, slot in stream:
                if res[idx] is not None:
                    raise WeirdState()
                res[idx] = slot

        for idx in self._locations:
            if res[idx] is not None:
                raise WeirdState()
            res[idx] = RandomBlock(idx)

        if None in res:
            raise WeirdState()

        return b''.join(map(bytes, res))


class GlomarStore:

    def __init__(self, data):
        loop = enumerate(chunks(data, BLOCK_SIZE))
        self._state = list(map(lambda x: Block(x[0], x[1]), loop))

    def get(self, key):
        nonce_hmac_key, hmac_key, stream_key = derive_keys(key)

        # Lets find the Nonce block
        nonce_block = None
        for idx, block in enumerate(self._state):
            if validate_block(nonce_hmac_key, block):
                nonce_block = block_to_nonceblock(block, nonce_hmac_key)
                break

        if not nonce_block:
            return

        # Now we need to identify the remaining blocks
        blocks = []
        for block in self._state:
            if validate_block(hmac_key, block):
                blocks.append(macblock_to_data(block))

        stream_nonce = nonce_block.get_nonce()
        c = ChaCha20(key=stream_key, nonce=stream_nonce, counter=0)

        res = b''
        for block in blocks:
            res += remove_header(c.decrypt(block))

        return res
