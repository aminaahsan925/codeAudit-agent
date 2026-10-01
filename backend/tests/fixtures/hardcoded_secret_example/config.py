"""Deliberately vulnerable: hardcoded secret. Fixture only.

The value below is obviously fake (it says so) and exists only so the
hardcoded-secret detector has something to find in tests.
"""

api_key = "sk_f4k3_n0tr3a1_us3th1s_d0notus3"
db_password = "f4k3dbpw_n0tr3a1"


def load_key_from_env():
    import os

    return os.environ.get("SERVICE_API_KEY", "")
