"""EasyPi backend application package.

The ASGI application is created only in :mod:`backend.main`. Keeping package
imports side-effect free is important: Alembic, maintenance commands and tests
all import ``app.*`` modules and must not create a second FastAPI application or
mutate the database merely by importing the package.
"""
