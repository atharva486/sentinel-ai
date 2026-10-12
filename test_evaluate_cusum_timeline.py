import unittest

from evaluate_cusum import sample_signal


class TestCusumEvaluationTimeline(unittest.TestCase):
    def test_samples_include_quiet_tail(self):
        starts = [100.0, 101.0, 102.0]

        samples = sample_signal(
            starts,
            window_s=10.0,
            interval_s=1.0,
            capture_end=105.0,
        )

        timestamps = [ts for ts, _ in samples]
        self.assertEqual(
            timestamps,
            [100.0, 101.0, 102.0, 103.0, 104.0, 105.0],
        )


if __name__ == "__main__":
    unittest.main()
