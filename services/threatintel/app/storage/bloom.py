"""
Redis-backed Bloom filter for IOC deduplication.

Uses a counting Bloom filter approach with multiple hash functions to
minimize false positives while allowing existence checks before
expensive storage writes.

AiSOC — open-source AI Security Operations Center (MIT License)
"""
from __future__ import annotations

import math
import structlog
from typing import Optional

import mmh3
import redis.asyncio as aioredis

logger = structlog.get_logger(__name__)

_DEFAULT_CAPACITY = 10_000_000  # 10M IOCs
_DEFAULT_ERROR_RATE = 0.001     # 0.1% false-positive rate
_BLOOM_KEY = "threatintel:bloom:iocs"


class RedisBloomFilter:
    """
    Async Redis Bloom filter for IOC deduplication.

    Bit positions are computed using MurmurHash3 with multiple seeds,
    matching a standard Bloom filter implementation.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        key: str = _BLOOM_KEY,
        capacity: int = _DEFAULT_CAPACITY,
        error_rate: float = _DEFAULT_ERROR_RATE,
    ) -> None:
        self._redis = redis_client
        self._key = key

        # Optimal Bloom filter parameters
        self._size = self._optimal_size(capacity, error_rate)
        self._num_hashes = self._optimal_hash_count(capacity, self._size)

        logger.info(
            "Bloom filter initialized",
            size=self._size,
            hash_functions=self._num_hashes,
            expected_capacity=capacity,
        )

    # ─── Public API ───────────────────────────────────────────────────────────

    async def add(self, item: str) -> None:
        """Add an item to the Bloom filter."""
        pipe = self._redis.pipeline(transaction=False)
        for bit in self._bit_positions(item):
            pipe.setbit(self._key, bit, 1)
        await pipe.execute()

    async def contains(self, item: str) -> bool:
        """
        Check if an item is probably in the filter.

        Returns True if possibly seen before (may have false positives),
        False if definitely not seen before.
        """
        pipe = self._redis.pipeline(transaction=False)
        for bit in self._bit_positions(item):
            pipe.getbit(self._key, bit)
        results = await pipe.execute()
        return all(results)

    async def add_batch(self, items: list[str]) -> list[bool]:
        """
        Add a batch of items.

        Returns a list of booleans indicating whether each item was
        *already* in the filter before this batch (True = duplicate).
        """
        duplicates: list[bool] = []
        for item in items:
            already_seen = await self.contains(item)
            duplicates.append(already_seen)
            if not already_seen:
                await self.add(item)
        return duplicates

    async def count_bits(self) -> int:
        """Return the number of set bits (approximation of stored items)."""
        return await self._redis.bitcount(self._key)

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _bit_positions(self, item: str) -> list[int]:
        """Calculate the bit positions for this item using k hash functions."""
        positions = []
        encoded = item.encode("utf-8")
        for seed in range(self._num_hashes):
            h = mmh3.hash(encoded, seed=seed, signed=False)
            positions.append(h % self._size)
        return positions

    @staticmethod
    def _optimal_size(capacity: int, error_rate: float) -> int:
        """Calculate optimal bit array size: m = -(n * ln(p)) / (ln(2)^2)"""
        return int(-capacity * math.log(error_rate) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_hash_count(capacity: int, size: int) -> int:
        """Calculate optimal hash function count: k = (m/n) * ln(2)"""
        return max(1, int((size / capacity) * math.log(2)))
