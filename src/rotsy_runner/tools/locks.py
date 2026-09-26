"""A small async readers–writer lock.

Scans *read* a scanner's installed binary and database; an install *writes*
them. Any number of scans may share a tool, but a database swap waits for
running scans to finish and holds new ones back until it is done — so a scan
never sees a database directory mid-replacement.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator


class RWLock:
    def __init__(self) -> None:
        self._cond = asyncio.Condition()
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @asynccontextmanager
    async def read(self) -> AsyncIterator[None]:
        async with self._cond:
            # Writers take priority, or a steady stream of scans could starve
            # a database update forever.
            await self._cond.wait_for(lambda: not self._writer and self._waiting_writers == 0)
            self._readers += 1
        try:
            yield
        finally:
            async with self._cond:
                self._readers -= 1
                self._cond.notify_all()

    @asynccontextmanager
    async def write(self) -> AsyncIterator[None]:
        async with self._cond:
            self._waiting_writers += 1
            try:
                await self._cond.wait_for(lambda: not self._writer and self._readers == 0)
            finally:
                self._waiting_writers -= 1
            self._writer = True
        try:
            yield
        finally:
            async with self._cond:
                self._writer = False
                self._cond.notify_all()
