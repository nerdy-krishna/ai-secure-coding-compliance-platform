"""Shared controls for opt-in real-infrastructure integration tests."""

from __future__ import annotations

import os
import unittest


INTEGRATION_ENABLED = os.getenv("SCCAP_RUN_INTEGRATION") == "1"
integration_test = unittest.skipUnless(
    INTEGRATION_ENABLED,
    "set SCCAP_RUN_INTEGRATION=1 and run this suite inside the app container",
)
