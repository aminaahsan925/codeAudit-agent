"""Deliberately vulnerable: unescaped HTML rendering (XSS). Fixture only."""

from markupsafe import mark_safe


def profile_page(username):
    html = "<h1>Hello, " + username + "</h1>"
    return mark_safe(html)


def greeting(name):
    from flask import render_template_string

    return render_template_string(f"<p>Hi {name}</p>")
