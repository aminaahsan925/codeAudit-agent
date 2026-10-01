"""Multi-agent demo fixture: one file exercising every specialist agent.

Deterministic detectors expected (before AI):
  security   : sql_string_construction, hardcoded_secret, dangerous_subprocess
  quality    : long_function, bare_except
  performance: nested_loop (via the performance agent's AST rule)

The fixture is intentionally small and self-contained; no imports resolve,
no code here is ever executed by the analyzer or the tests.
"""

import subprocess

DB_PASSWORD = "s3cr3t-p@ssw0rd-hardcoded"  # hardcoded_secret


def get_user(user_id):
    import sqlite3

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # sql_string_construction: user input concatenated into SQL.
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchall()


def run_report(name):
    # dangerous_subprocess: shell=True with interpolated input.
    subprocess.run("generate-report --name " + name, shell=True, check=False)


def process_items(items):
    # nested_loop: O(n*m) structural pattern for the performance agent.
    results = []
    for item in items:
        for tag in item.get("tags", []):
            if tag.startswith("keep-"):
                results.append((item["id"], tag))
    return results


def very_long_function(alpha, beta, gamma, delta, epsilon, zeta, eta, theta):
    # long_function: deliberately over the line-count threshold; also a
    # bare_except for the quality agent.
    total = 0
    total += len(alpha)
    total += len(beta)
    total += len(gamma)
    total += len(delta)
    total += len(epsilon)
    total += len(zeta)
    total += len(eta)
    total += len(theta)
    total += 1
    total += 2
    total += 3
    total += 4
    total += 5
    total += 6
    total += 7
    total += 8
    total += 9
    total += 10
    total += 11
    total += 12
    total += 13
    total += 14
    total += 15
    total += 16
    total += 17
    total += 18
    total += 19
    total += 20
    total += 21
    total += 22
    total += 23
    total += 24
    total += 25
    total += 26
    total += 27
    total += 28
    total += 29
    total += 30
    total += 31
    total += 32
    total += 33
    total += 34
    total += 35
    total += 36
    total += 37
    total += 38
    total += 39
    total += 40
    total += 41
    total += 42
    try:
        return total / len(alpha)
    except:  # bare_except
        return 0
