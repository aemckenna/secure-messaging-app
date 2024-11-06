import os
import sqlite3
from flask import g

# Database connection function for SQLite3
def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect(
            'secure_messaging.db',  # Path to your SQLite3 database file
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row  # This allows access to columns by name
    return g.db

# Close the database connection after each request
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()