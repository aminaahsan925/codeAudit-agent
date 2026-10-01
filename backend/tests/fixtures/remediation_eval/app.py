"""Deliberately vulnerable fixture for risk-recalculation tests. Fake data only."""


def handle(payload):
    return eval(payload)
