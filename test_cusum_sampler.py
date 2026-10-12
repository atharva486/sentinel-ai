import unittest

from m2_triggers.cusum import CUSUM
from m2_triggers.cusum_sampler import CusumSampler


class TestCusumSampler(unittest.TestCase):
    def test_repeated_calls_within_interval_do_not_repeat_sample(self):
        detector = CUSUM(mu=0, sigma=1, k=0, h=100)
        sampler = CusumSampler(detector, interval_s=1)

        sampler.update(10.0, 1.0)
        before = detector.s_pos

        sampler.update(10.2, 9.0)

        self.assertEqual(detector.s_pos, before)

    def test_next_interval_adds_one_sample(self):
        detector = CUSUM(mu=0, sigma=1, k=0, h=100)
        sampler = CusumSampler(detector, interval_s=1)

        sampler.update(10.0, 1.0)
        before = detector.s_pos

        sampler.update(11.0, 2.0)

        self.assertAlmostEqual(detector.s_pos - before, 2.0)

    def test_invalid_interval_is_rejected(self):
        with self.assertRaises(ValueError):
            CusumSampler(CUSUM(mu=0, sigma=1), interval_s=0)


if __name__ == "__main__":
    unittest.main()
