"""Deliberately vulnerable: eval/exec on input. Fixture only."""


def calculate(expression):
    return eval(expression)


def run_plugin(code):
    exec(code)
