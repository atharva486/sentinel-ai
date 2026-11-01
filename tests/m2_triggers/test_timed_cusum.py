import unittest

from m2_triggers.cusum import CUSUM
from m2_triggers.timed_cusum import TimedCusum


class TestTimedCusum(unittest.TestCase):
    def make_detector(self):
        return CUSUM(mu=0.0, sigma=1.0, k=0.0, h=1000.0)

    def test_samples_at_exact_timestamp(self):
        detector = self.make_detector()
        timed = TimedCusum(detector, window_s=10, interval_s=1)
        timed.on_connect(100.0)

        timed.advance(100.0)
        self.assertAlmostEqual(detector.s_pos, 0.1)

        before = detector.s_pos
        timed.advance(100.5)
        self.assertAlmostEqual(detector.s_pos, before)

        timed.advance(101.0)
        self.assertAlmostEqual(detector.s_pos - before, 0.1)

    def test_delayed_advance_processes_each_due_tick(self):
        detector = self.make_detector()
        timed = TimedCusum(detector, window_s=10, interval_s=1)
        timed.on_connect(100.0)

        timed.advance(100.0)
        before = detector.s_pos

        timed.advance(103.0)

        # Scheduled samples 101, 102 and 103 each see one start / 10 seconds.
        self.assertAlmostEqual(detector.s_pos - before, 0.3)
        self.assertAlmostEqual(timed.next_sample_ts, 104.0)

    def test_rolling_window_excludes_old_connections(self):
        detector = self.make_detector()
        timed = TimedCusum(detector, window_s=10, interval_s=1)
        timed.on_connect(89.0)
        timed.on_connect(100.0)

        timed.advance(100.0)

        # Only the connection at 100 is inside (90, 100].
        self.assertAlmostEqual(detector.s_pos, 0.1)

    def test_invalid_interval_is_rejected(self):
        with self.assertRaises(ValueError):
            TimedCusum(self.make_detector(), interval_s=0)

    def test_invalid_window_is_rejected(self):
        with self.assertRaises(ValueError):
            TimedCusum(self.make_detector(), window_s=0)


if __name__ == "__main__":
    unittest.main()
