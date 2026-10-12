
"""Integration tests for Module 2 Redis counters.

Requires a running Redis instance and the redis Python package.
Set REDIS_HOST to the Redis hostname reachable from this process.
"""
import os
import time
import unittest
import uuid

import redis

from m2_triggers.counters import (
    hit,
    track_open_connections,
    remove_open_connection,
)


class TestRedisCounters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        cls.client.ping()

    def setUp(self):
        self.key = f"test:m2:{uuid.uuid4().hex}"
        self.entity = f"test-entity-{uuid.uuid4().hex}"

    def tearDown(self):
        self.client.delete(self.key, f"conns:{self.entity}")

    def test_rate_limit_rejects_excess_hits(self):
        self.assertEqual(hit(self.client, self.key, 10, 2), (True, 1))
        self.assertEqual(hit(self.client, self.key, 10, 2), (True, 2))
        self.assertEqual(hit(self.client, self.key, 10, 2), (False, 2))

    def test_window_expiry_allows_new_hit(self):
        self.assertEqual(hit(self.client, self.key, 1, 1), (True, 1))
        self.assertEqual(hit(self.client, self.key, 1, 1), (False, 1))
        time.sleep(1.2)
        self.assertEqual(hit(self.client, self.key, 1, 1), (True, 1))

    def test_connection_tracking_and_removal(self):
        self.assertEqual(
            track_open_connections(self.client, self.entity, "conn-1"), 1
        )
        self.assertEqual(
            track_open_connections(self.client, self.entity, "conn-2"), 2
        )
        self.assertEqual(
            remove_open_connection(self.client, self.entity, "conn-1"), 1
        )


if __name__ == "__main__":
    unittest.main()