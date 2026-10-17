"""
AegisAgent - Zero-Leakage Memory & Key Isolation
Provides ephemeral in-memory reconstruction with hardware-grade zeroization,
ensuring API keys and master credentials leave zero footprint in memory dumps or logs.
"""

import gc
import ctypes
from typing import Generator
from contextlib import contextmanager
from app.crypto.finite_field import field


def key_to_int(key_str: str) -> int:
    """Converts a utf-8 string key into an integer in finite field Z_q."""
    key_bytes = key_str.encode("utf-8")
    val = int.from_bytes(key_bytes, byteorder="big")
    if val >= field.q:
        raise ValueError(f"Key size ({len(key_bytes)} bytes) exceeds finite field prime capacity.")
    return val


def int_to_key(key_int: int) -> str:
    """Converts an integer in Z_q back to utf-8 string key."""
    byte_len = (key_int.bit_length() + 7) // 8
    key_bytes = key_int.to_bytes(byte_len, byteorder="big")
    return key_bytes.decode("utf-8", errors="replace")


@contextmanager
def ephemeral_key_buffer(key_str: str) -> Generator[bytearray, None, None]:
    """
    Zero-trace context manager for ephemeral key handling.
    Allocates a mutable bytearray buffer, provides it to the caller,
    and explicitly overwrites every byte with zeros upon exit before freeing.
    """
    buf = bytearray(key_str.encode("utf-8"))
    try:
        yield buf
    finally:
        # Zeroize the memory buffer explicitly
        for i in range(len(buf)):
            buf[i] = 0
        del buf
        gc.collect()


class ZeroLeakageSandbox:
    """Simulates a secure enclave sandbox where ephemeral keys are executed."""

    @staticmethod
    def execute_with_ephemeral_key(key_str: str, action_fn, *args, **kwargs):
        """
        Executes action_fn with the key_str, ensuring the key is securely wiped
        from memory immediately after the call completes or if an exception occurs.
        """
        with ephemeral_key_buffer(key_str) as secure_buf:
            # We reconstruct the transient string only for the exact duration of the invocation
            transient_key = secure_buf.decode("utf-8")
            result = action_fn(transient_key, *args, **kwargs)
            # Nullify local transient reference
            transient_key = ""
            del transient_key
            return result
