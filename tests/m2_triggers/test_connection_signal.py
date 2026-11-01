import unittest

from m2_triggers.connection_signal import connection_open_rate


class TestConnectionSignal(unittest.TestCase):
    def test_counts_only_starts_inside_window(self):
        starts = [89.9, 90.0, 91.0, 95.0, 100.0]
        self.assertAlmostEqual(
            connection_open_rate(starts, now=100.0, window_s=10.0),
            0.3,
        )

    def test_future_starts_are_excluded(self):
        self.assertAlmostEqual(
            connection_open_rate(
                [99.0, 101.0], now=100.0, window_s=10.0
            ),
            0.1,
        )

    def test_invalid_window_is_rejected(self):
        with self.assertRaises(ValueError):
            connection_open_rate([], now=100.0, window_s=0)


if __name__ == "__main__":
    unittest.main()
