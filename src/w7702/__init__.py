"""7702-safety: executable conformance suite for EIP-7702 security standards."""

__version__ = "0.1.0"

from . import erc8010, markers  # noqa: F401

__all__ = ["markers", "erc8010"]
