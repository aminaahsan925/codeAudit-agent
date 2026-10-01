"""Fixture for AI integration tests. Fake data only, toy vulnerabilities only."""

import os


def get_item(name, cursor):
    cursor.execute("SELECT * FROM items WHERE name = '" + name + "'")
    return cursor.fetchall()


def list_items():
    return ["alpha", "beta"]


def get_config():
    return {"debug": True}
