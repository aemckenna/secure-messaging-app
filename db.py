import os
from flask import g
import psycopg2

secret_password = os.environ.get('postgresDbPassword')

# Database connection function for PostgreSQL
def get_db_connection():
    if 'db' not in g:
        g.db = psycopg2.connect(
            dbname='messaging-app',
            user='ashermckenna',
            password=secret_password,
            host='localhost',
            port='6000'
        )
    return g.db

# Close the database connection after each request
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()