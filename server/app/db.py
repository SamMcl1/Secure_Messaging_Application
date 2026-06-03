import psycopg2
from psycopg2 import pool
from supabase import create_client, Client
from flask import g, current_app


_pool: pool.SimpleConnectionPool | None = None
_supabase: Client | None = None


def init_db(app):
    global _pool, _supabase

    _pool = pool.SimpleConnectionPool( # Database connection encrypted in transit with SSL, and connection pooling for efficiency. 
        minconn=1,
        maxconn=10,
        dsn=app.config['DATABASE_URL'],
        sslmode='require',
    )

    _supabase = create_client(
        app.config['SUPABASE_URL'],
        app.config['SUPABASE_SERVICE_KEY'],
    )


def get_supabase() -> Client:
    """Return the Supabase client (for REST/realtime operations)."""
    return _supabase


def get_conn():
    """Return a raw psycopg2 connection from the pool (stored on Flask g)."""
    if 'db_conn' not in g:
        g.db_conn = _pool.getconn()
        g.db_conn.autocommit = False
    return g.db_conn


def close_conn(e=None):
    conn = g.pop('db_conn', None)
    if conn is not None:
        if e is None:
            conn.commit()
        else:
            conn.rollback() # ACID rollback on error to prevent partial writes, which could cause data corruption or security issues. 
        _pool.putconn(conn)


def query(sql: str, params: tuple = ()) -> list[dict]:
    """Execute a SELECT and return rows as dicts."""
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(sql, params)
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def execute(sql: str, params: tuple = ()) -> int | None:
    """Execute INSERT/UPDATE/DELETE and return the first column of the first row (e.g. RETURNING id)."""
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(sql, params)
        if cur.description:
            row = cur.fetchone()
            return row[0] if row else None
        return None
