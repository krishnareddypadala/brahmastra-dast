"""
BRAHMASTRA — Server Configuration

Reads environment variables for the server layer. The only setting that
actually matters today is the PostgreSQL connection string; keep this file
minimal so there is one obvious place to add more knobs later.

Environment variables:
  BRAHMASTRA_DB_URL   PostgreSQL DSN used by server/db.py.
                      Defaults to a local PG container bound to 127.0.0.1:5432
                      with username/password/database all set to 'brahmastra'
                      (matches the docker run command in the deploy docs).
"""

import os

BRAHMASTRA_DB_URL: str = os.getenv(
    "BRAHMASTRA_DB_URL",
    "postgresql://brahmastra:brahmastra@127.0.0.1:5432/brahmastra",
)
