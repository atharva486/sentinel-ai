"""CUSUM detector for sustained changes in a numeric signal."""


class CUSUM:
    """Detect sustained deviations from a baseline mean."""

    def __init__(
        self,
        mu: float,
        sigma: float,
        k: float = 0.5,
        h: float = 5.0,
    ) -> None:
        if sigma <= 0:
            raise ValueError("sigma must be greater than zero")
        if k < 0:
            raise ValueError("k must be non-negative")
        if h <= 0:
            raise ValueError("h must be greater than zero")

        self.mu = float(mu)
        self.sigma = float(sigma)
        self.k = k * self.sigma
        self.h = h * self.sigma
        self.s_pos = 0.0
        self.s_neg = 0.0

    def update(self, x: float) -> bool:
        """Return True when a sustained upward or downward shift is detected."""
        x = float(x)

        self.s_pos = max(0.0, self.s_pos + (x - self.mu - self.k))
        self.s_neg = max(0.0, self.s_neg + (self.mu - x - self.k))

        if self.s_pos > self.h or self.s_neg > self.h:
            self.s_pos = 0.0
            self.s_neg = 0.0
            return True

        return False

    def reset(self) -> None:
        """Clear accumulated evidence without changing baseline parameters."""
        self.s_pos = 0.0
        self.s_neg = 0.0
