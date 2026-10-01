"""Deliberately vulnerable: SQL string construction. Fixture only."""


def get_user_unsafe(user_id, cursor):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchall()


def search_unsafe(term, cursor):
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return cursor.fetchall()


def get_user_safe(user_id, cursor):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchall()
