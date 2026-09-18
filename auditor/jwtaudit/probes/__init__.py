"""Probe package.

Each probe module registers itself with the registry in `base.py` at import
time. Importing this package imports every probe module in run order.
"""

from . import none_alg  # noqa: F401  (registers the probe at import time)
from . import weak_secret  # noqa: F401
from . import alg_confusion  # noqa: F401
from . import signature_bypass  # noqa: F401
from . import null_signature  # noqa: F401
from . import jwk_injection  # noqa: F401
from . import expiration  # noqa: F401

__all__ = [
    "none_alg",
    "weak_secret",
    "alg_confusion",
    "signature_bypass",
    "null_signature",
    "jwk_injection",
    "expiration",
]
