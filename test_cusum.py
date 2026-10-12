from m2_triggers.cusum import CUSUM

# Stable baseline should not immediately trigger.
detector = CUSUM(mu=10.0, sigma=2.0)
assert not detector.update(10.0)

# Sustained high values should eventually trigger.
detector = CUSUM(mu=10.0, sigma=2.0)
results = [detector.update(25.0) for _ in range(5)]
assert any(results), "CUSUM did not detect a sustained upward shift"

# Sustained low values should eventually trigger.
detector = CUSUM(mu=10.0, sigma=2.0)
results = [detector.update(-5.0) for _ in range(5)]
assert any(results), "CUSUM did not detect a sustained downward shift"

# Invalid baseline scale should be rejected.
try:
    CUSUM(mu=10.0, sigma=0.0)
except ValueError:
    pass
else:
    raise AssertionError("CUSUM should reject sigma=0")

print("PASS: stable baseline")
print("PASS: upward shift")
print("PASS: downward shift")
print("PASS: invalid sigma rejected")
print("All CUSUM checks passed")
