"""Recover an EVM private key with a small number of missing hex digits.

Four explicit input modes are supported:

* pattern: a 64-character key containing ``?`` at known missing positions;
* fragment: one contiguous key fragment whose offset in the key is unknown.
* sequence: all surviving characters in order, with missing positions unknown.
* two_blocks: two intact fragments in either order, with gaps anywhere.

The search is intentionally CPU-bound and runs entirely on the local machine.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import itertools
import json
import math
import multiprocessing
import os
import re
import socket
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Literal

from eth_keys import keys
from eth_utils import keccak


HEX_CHARS = frozenset("0123456789abcdef")
SECP256K1_ORDER = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)
DEFAULT_BATCH_SIZE = 1_000
DEFAULT_MAX_CANDIDATES = 100_000_000
DEFAULT_CHECKPOINT_INTERVAL = 5.0
DEFAULT_CHECKPOINT_PATH = (
    Path(__file__).resolve().parent
    / "runtime" / "private-key-recovery" / "checkpoints.sqlite3"
)
ALGORITHM_VERSION = 2
LEASE_STALE_SECONDS = 30.0

# Preserve the current local example when the script is launched without CLI input.
DEFAULT_FRAGMENT = "3c9a90bb10e7605f2ed846faeb63a122ba3e851dbf78ebb463eb9377932e1e"
DEFAULT_TARGET_ADDRESS = "9b73E95909Be63F02b06130716384c3030C74D8D"

SearchMode = Literal["pattern", "fragment", "sequence", "two_blocks"]
ProgressCallback = Callable[["ProgressSnapshot"], None]


@dataclass(frozen=True)
class SearchSpec:
    mode: SearchMode
    key_spec: str
    patterns: tuple[str, ...]
    layout_count: int
    missing_count: int
    total_candidates: int
    block_b: str | None = None


@dataclass(frozen=True)
class WorkBatch:
    pattern: str
    start: int
    stop: int
    batch_id: int = 0
    layout_id: int = 0


@dataclass(frozen=True)
class BatchResult:
    tested_count: int
    found_key: str | None = None
    batch_id: int = 0
    found_assignment_index: int | None = None


@dataclass(frozen=True)
class ProgressSnapshot:
    completed: int
    total: int
    elapsed_seconds: float
    candidates_per_second: float
    eta_seconds: float | None

    @property
    def percent(self) -> float:
        return (self.completed / self.total) * 100 if self.total else 100.0


_worker_target_address: bytes | None = None
_worker_stop_event: Any = None


def _strip_optional_0x(value: str) -> str:
    stripped = value.strip()
    return stripped[2:] if stripped[:2].lower() == "0x" else stripped


def normalize_address(address: str) -> bytes:
    """Validate an EVM address and return its canonical 20-byte value."""
    if not isinstance(address, str):
        raise TypeError("Target address must be a string.")

    normalized = _strip_optional_0x(address)
    if len(normalized) != 40 or re.fullmatch(r"[0-9a-fA-F]{40}", normalized) is None:
        raise ValueError("Target address must contain exactly 40 hexadecimal characters.")
    return bytes.fromhex(normalized)


def _normalize_private_key(private_key_hex: str) -> str:
    if not isinstance(private_key_hex, str):
        raise TypeError("Private key must be a string.")

    normalized = _strip_optional_0x(private_key_hex).lower()
    if len(normalized) != 64 or any(char not in HEX_CHARS for char in normalized):
        raise ValueError("Private key must contain exactly 64 hexadecimal characters.")
    return normalized


def _derive_address_unchecked(private_key_hex: str) -> bytes:
    private_key_bytes = bytes.fromhex(private_key_hex)
    public_key = keys.PrivateKey(private_key_bytes).public_key
    return keccak(public_key.to_bytes())[12:]


def private_key_to_address(private_key_hex: str) -> bytes:
    """Derive the canonical 20-byte EVM address for a valid private key."""
    normalized = _normalize_private_key(private_key_hex)
    scalar = int(normalized, 16)
    if not 1 <= scalar < SECP256K1_ORDER:
        raise ValueError("Private key scalar is outside the secp256k1 range.")
    return _derive_address_unchecked(normalized)


def _normalize_block(block: str, name: str) -> str:
    if not isinstance(block, str):
        raise TypeError(f"Block {name} must be a string.")
    normalized = _strip_optional_0x(block).lower()
    if not normalized:
        raise ValueError(f"Block {name} cannot be empty.")
    if any(char not in HEX_CHARS for char in normalized):
        raise ValueError(f"Block {name} may only contain hexadecimal characters.")
    return normalized


def _two_block_patterns(block_a: str, block_b: str) -> tuple[str, ...]:
    missing = 64 - len(block_a) - len(block_b)
    seen: set[str] = set()
    patterns: list[str] = []
    orders = ((block_a, block_b),)
    if block_a != block_b:
        orders += ((block_b, block_a),)
    for first, second in orders:
        for gap in range(missing + 1):
            for prefix in range(missing - gap + 1):
                suffix = missing - gap - prefix
                pattern = "?" * prefix + first + "?" * gap + second + "?" * suffix
                if pattern not in seen:
                    seen.add(pattern)
                    patterns.append(pattern)
    return tuple(patterns)


def _two_block_priority_layout_ids(spec: SearchSpec) -> Iterator[int]:
    """Schedule adjacent blocks first without changing saved layout IDs."""
    block_a, block_b = spec.key_spec, spec.block_b
    if block_b is None:
        raise ValueError("Two-block search spec is missing block B.")
    orders = ((block_a, block_b),)
    if block_a != block_b:
        orders += ((block_b, block_a),)
    layout_by_pattern = {pattern: i for i, pattern in enumerate(spec.patterns)}
    scheduled: set[int] = set()

    # Keep the original pattern tuple and batch IDs for existing checkpoints.
    for adjacent in (True, False):
        for first, second in orders:
            gaps = (0,) if adjacent else range(1, spec.missing_count + 1)
            for gap in gaps:
                for prefix in range(spec.missing_count - gap + 1):
                    suffix = spec.missing_count - gap - prefix
                    pattern = "?" * prefix + first + "?" * gap + second + "?" * suffix
                    layout_id = layout_by_pattern[pattern]
                    if layout_id not in scheduled:
                        scheduled.add(layout_id)
                        yield layout_id


def build_search_spec(
    key_spec: str | tuple[str, str], mode: SearchMode = "pattern"
) -> SearchSpec:
    """Validate a key specification and calculate its complete search space."""
    if mode not in ("pattern", "fragment", "sequence", "two_blocks"):
        raise ValueError(
            "Search mode must be 'pattern', 'fragment', 'sequence', or 'two_blocks'."
        )
    if mode == "two_blocks":
        if not isinstance(key_spec, (tuple, list)) or len(key_spec) != 2:
            raise TypeError("Two-block mode requires exactly two blocks.")
        block_a = _normalize_block(key_spec[0], "A")
        block_b = _normalize_block(key_spec[1], "B")
        missing_count = 64 - len(block_a) - len(block_b)
        if missing_count < 0:
            raise ValueError("The two blocks cannot exceed 64 characters combined.")
        patterns = _two_block_patterns(block_a, block_b)
        return SearchSpec(
            mode=mode,
            key_spec=block_a,
            patterns=patterns,
            layout_count=len(patterns),
            missing_count=missing_count,
            total_candidates=len(patterns) * 16**missing_count,
            block_b=block_b,
        )

    if not isinstance(key_spec, str):
        raise TypeError("Key specification must be a string.")

    normalized = _strip_optional_0x(key_spec).lower()

    if mode == "pattern":
        if len(normalized) != 64:
            raise ValueError("A key pattern must contain exactly 64 characters.")
        if any(char not in HEX_CHARS and char != "?" for char in normalized):
            raise ValueError("A key pattern may only contain hexadecimal characters and '?'.")
        patterns = (normalized,)
        layout_count = 1
    else:
        if not normalized:
            raise ValueError(f"A key {mode} cannot be empty.")
        if len(normalized) > 64:
            raise ValueError(f"A key {mode} cannot be longer than 64 characters.")
        if any(char not in HEX_CHARS for char in normalized):
            raise ValueError(f"A key {mode} may only contain hexadecimal characters.")

        missing_count = 64 - len(normalized)
        if mode == "fragment":
            patterns = tuple(
                "?" * prefix_length
                + normalized
                + "?" * (missing_count - prefix_length)
                for prefix_length in range(missing_count + 1)
            )
            layout_count = len(patterns)
        else:
            # Sequence layouts can number in the millions; generate them lazily.
            patterns = ()
            layout_count = math.comb(64, missing_count)

    if mode == "pattern":
        missing_count = normalized.count("?")
    candidates_per_pattern = 16**missing_count
    total_candidates = layout_count * candidates_per_pattern
    return SearchSpec(
        mode=mode,
        key_spec=normalized,
        patterns=patterns,
        layout_count=layout_count,
        missing_count=missing_count,
        total_candidates=total_candidates,
    )


def _sequence_pattern(
    sequence: str, unknown_positions: tuple[int, ...]
) -> str:
    unknown_iter = iter(unknown_positions)
    next_unknown = next(unknown_iter, None)
    known_iter = iter(sequence)
    pattern: list[str] = []

    for position in range(64):
        if position == next_unknown:
            pattern.append("?")
            next_unknown = next(unknown_iter, None)
        else:
            pattern.append(next(known_iter))
    return "".join(pattern)


def _unrank_combination(n: int, k: int, rank: int) -> tuple[int, ...]:
    """Return the lexicographic combination at zero-based ``rank``."""
    if rank < 0 or rank >= math.comb(n, k):
        raise IndexError("Layout index is outside the search space.")
    positions: list[int] = []
    lower = 0
    for remaining in range(k, 0, -1):
        for position in range(lower, n - remaining + 1):
            count = math.comb(n - position - 1, remaining - 1)
            if rank < count:
                positions.append(position)
                lower = position + 1
                break
            rank -= count
    return tuple(positions)


def pattern_for_layout(spec: SearchSpec, layout_id: int) -> str:
    """Build one layout directly, including deep sequence checkpoint resumes."""
    if layout_id < 0 or layout_id >= spec.layout_count:
        raise IndexError("Layout index is outside the search space.")
    if spec.mode == "sequence":
        return _sequence_pattern(
            spec.key_spec, _unrank_combination(64, spec.missing_count, layout_id)
        )
    return spec.patterns[layout_id]


def iter_patterns(spec: SearchSpec) -> Iterator[str]:
    """Yield every positional layout without materializing sequence layouts."""
    if spec.mode != "sequence":
        yield from spec.patterns
        return

    for unknown_positions in itertools.combinations(range(64), spec.missing_count):
        yield _sequence_pattern(spec.key_spec, unknown_positions)


def fill_pattern(pattern: str, index: int) -> str:
    """Fill a validated pattern using ``index`` as a fixed-width hex counter."""
    unknown_positions = tuple(i for i, char in enumerate(pattern) if char == "?")
    combination_count = 16 ** len(unknown_positions)
    if index < 0 or index >= combination_count:
        raise ValueError(f"Pattern index must be in the range 0..{combination_count - 1}.")
    return _fill_pattern(pattern, unknown_positions, index)


def _fill_pattern(pattern: str, unknown_positions: tuple[int, ...], index: int) -> str:
    if not unknown_positions:
        return pattern

    replacement = f"{index:0{len(unknown_positions)}x}"
    candidate = list(pattern)
    for position, char in zip(unknown_positions, replacement):
        candidate[position] = char
    return "".join(candidate)


def iter_work_batches(
    spec: SearchSpec,
    batch_size: int,
    *,
    start_batch_id: int = 0,
    completed_batch_ids: frozenset[int] = frozenset(),
) -> Iterator[WorkBatch]:
    """Yield bounded work without materializing the whole candidate space."""
    if batch_size <= 0:
        raise ValueError("Batch size must be greater than zero.")

    combinations_per_pattern = 16**spec.missing_count
    batches_per_layout = math.ceil(combinations_per_pattern / batch_size)
    total_batches = spec.layout_count * batches_per_layout
    if start_batch_id < 0 or start_batch_id > total_batches:
        raise ValueError("Start batch ID is outside the search space.")
    if spec.mode == "two_blocks":
        for layout_id in _two_block_priority_layout_ids(spec):
            layout_start = layout_id * batches_per_layout
            first_chunk = max(0, start_batch_id - layout_start)
            if first_chunk >= batches_per_layout:
                continue
            pattern = pattern_for_layout(spec, layout_id)
            for chunk_id in range(first_chunk, batches_per_layout):
                batch_id = layout_start + chunk_id
                if batch_id in completed_batch_ids:
                    continue
                start = chunk_id * batch_size
                yield WorkBatch(
                    pattern=pattern,
                    start=start,
                    stop=min(start + batch_size, combinations_per_pattern),
                    batch_id=batch_id,
                    layout_id=layout_id,
                )
        return

    last_layout_id = -1
    pattern = ""
    for batch_id in range(start_batch_id, total_batches):
        if batch_id in completed_batch_ids:
            continue
        layout_id, chunk_id = divmod(batch_id, batches_per_layout)
        if layout_id != last_layout_id:
            pattern = pattern_for_layout(spec, layout_id)
            last_layout_id = layout_id
        start = chunk_id * batch_size
        yield WorkBatch(
            pattern=pattern,
            start=start,
            stop=min(start + batch_size, combinations_per_pattern),
            batch_id=batch_id,
            layout_id=layout_id,
        )


def _init_worker(target_address: bytes, stop_event: Any) -> None:
    global _worker_target_address, _worker_stop_event
    _worker_target_address = target_address
    _worker_stop_event = stop_event


def search_batch(batch: WorkBatch) -> BatchResult:
    """Search one batch. Worker state is installed by ``_init_worker``."""
    if _worker_target_address is None or _worker_stop_event is None:
        raise RuntimeError("Worker has not been initialized.")

    unknown_positions = tuple(i for i, char in enumerate(batch.pattern) if char == "?")
    tested = 0

    for index in range(batch.start, batch.stop):
        if tested % 256 == 0 and _worker_stop_event.is_set():
            break

        candidate = _fill_pattern(batch.pattern, unknown_positions, index)
        tested += 1
        scalar = int(candidate, 16)
        if not 1 <= scalar < SECP256K1_ORDER:
            continue

        if _derive_address_unchecked(candidate) == _worker_target_address:
            _worker_stop_event.set()
            return BatchResult(
                tested_count=tested,
                found_key=candidate,
                batch_id=batch.batch_id,
                found_assignment_index=index,
            )

    return BatchResult(tested_count=tested, batch_id=batch.batch_id)


def _make_progress(
    completed: int, total: int, start_time: float, initial_completed: int = 0
) -> ProgressSnapshot:
    elapsed = max(time.monotonic() - start_time, 0.0)
    rate = (completed - initial_completed) / elapsed if elapsed > 0 else 0.0
    remaining = max(total - completed, 0)
    eta = remaining / rate if rate > 0 else None
    return ProgressSnapshot(
        completed=completed,
        total=total,
        elapsed_seconds=elapsed,
        candidates_per_second=rate,
        eta_seconds=eta,
    )


def _format_progress(snapshot: ProgressSnapshot) -> str:
    eta = f"{snapshot.eta_seconds:.1f}s" if snapshot.eta_seconds is not None else "unknown"
    return (
        f"Checked {snapshot.completed:,}/{snapshot.total:,} "
        f"({snapshot.percent:.2f}%) | {snapshot.candidates_per_second:,.0f}/s | ETA {eta}"
    )


def _search_fingerprint(spec: SearchSpec, target: bytes, batch_size: int) -> str:
    input_value: str | list[str]
    if spec.mode == "two_blocks":
        input_value = [spec.key_spec, spec.block_b or ""]
    else:
        input_value = spec.key_spec
    input_hash = hashlib.sha256(
        json.dumps(input_value, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    payload = [ALGORITHM_VERSION, spec.mode, input_hash, target.hex(), batch_size]
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":")).encode("ascii")
    ).hexdigest()


class CheckpointStore:
    """Main-process-only durable batch frontier and search lease."""

    def __init__(
        self,
        path: str | Path,
        spec: SearchSpec,
        target: bytes,
        batch_size: int,
        total_batches: int,
        restart: bool,
    ) -> None:
        checkpoint_path = Path(path)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(checkpoint_path, timeout=10, isolation_level=None)
        self.fingerprint = _search_fingerprint(spec, target, batch_size)
        self.token = uuid.uuid4().hex
        self.frontier = 0
        self.completed_count = 0
        self.completed_out_of_order: frozenset[int] = frozenset()
        self.status = "running"
        self.found_layout_id: int | None = None
        self.found_assignment_index: int | None = None
        self.pending: dict[int, int] = {}
        self.last_flush = time.monotonic()
        self.last_heartbeat = self.last_flush
        self.has_lease = False
        try:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise sqlite3.DatabaseError("Checkpoint integrity check failed.")
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS search_runs (
                    fingerprint TEXT PRIMARY KEY,
                    algorithm_version INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    batch_size TEXT NOT NULL,
                    total_batches TEXT NOT NULL,
                    total_candidates TEXT NOT NULL,
                    frontier TEXT NOT NULL,
                    completed_candidates TEXT NOT NULL,
                    status TEXT NOT NULL,
                    found_layout_id TEXT,
                    found_assignment_index TEXT,
                    lease_host TEXT,
                    lease_pid INTEGER,
                    lease_token TEXT,
                    heartbeat REAL
                );
                CREATE TABLE IF NOT EXISTS completed_out_of_order (
                    fingerprint TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    PRIMARY KEY (fingerprint, batch_id),
                    FOREIGN KEY (fingerprint) REFERENCES search_runs(fingerprint)
                );
                """
            )
            now = time.time()
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                """SELECT frontier, completed_candidates, status,
                          found_layout_id, found_assignment_index, heartbeat,
                          lease_host, lease_pid
                   FROM search_runs WHERE fingerprint=?""",
                (self.fingerprint,),
            ).fetchone()
            if row is not None and row[2] == "running" and row[5] is not None:
                if now - row[5] < LEASE_STALE_SECONDS:
                    raise RuntimeError(
                        f"This search is already running on {row[6]} (PID {row[7]})."
                    )
            if restart and row is not None:
                self.connection.execute(
                    "DELETE FROM completed_out_of_order WHERE fingerprint=?",
                    (self.fingerprint,),
                )
                self.connection.execute(
                    "DELETE FROM search_runs WHERE fingerprint=?", (self.fingerprint,)
                )
                row = None
            if row is None:
                self.connection.execute(
                    """INSERT INTO search_runs VALUES
                    (?, ?, ?, ?, ?, ?, '0', '0', 'running', NULL, NULL, ?, ?, ?, ?)""",
                    (
                        self.fingerprint,
                        ALGORITHM_VERSION,
                        spec.mode,
                        str(batch_size),
                        str(total_batches),
                        str(spec.total_candidates),
                        socket.gethostname(),
                        os.getpid(),
                        self.token,
                        now,
                    ),
                )
                self.has_lease = True
            else:
                self.frontier = int(row[0])
                self.completed_count = int(row[1])
                self.status = row[2]
                self.found_layout_id = int(row[3]) if row[3] is not None else None
                self.found_assignment_index = int(row[4]) if row[4] is not None else None
                if self.status == "running":
                    self.connection.execute(
                        """UPDATE search_runs SET lease_host=?, lease_pid=?,
                           lease_token=?, heartbeat=? WHERE fingerprint=?""",
                        (socket.gethostname(), os.getpid(), self.token, now, self.fingerprint),
                    )
                    self.has_lease = True
                    self.completed_out_of_order = frozenset(
                        int(item[0])
                        for item in self.connection.execute(
                            "SELECT batch_id FROM completed_out_of_order WHERE fingerprint=?",
                            (self.fingerprint,),
                        )
                    )
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            self.connection.close()
            raise

    def add_completed(self, batch_id: int, tested_count: int) -> None:
        if batch_id >= self.frontier and batch_id not in self.completed_out_of_order:
            self.pending[batch_id] = tested_count

    def flush(self) -> None:
        if not self.has_lease:
            return
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            for batch_id in self.pending:
                self.connection.execute(
                    """INSERT OR IGNORE INTO completed_out_of_order
                       (fingerprint, batch_id) VALUES (?, ?)""",
                    (self.fingerprint, str(batch_id)),
                )
            frontier = self.frontier
            while self.connection.execute(
                """SELECT 1 FROM completed_out_of_order
                   WHERE fingerprint=? AND batch_id=?""",
                (self.fingerprint, str(frontier)),
            ).fetchone() is not None:
                self.connection.execute(
                    """DELETE FROM completed_out_of_order
                       WHERE fingerprint=? AND batch_id=?""",
                    (self.fingerprint, str(frontier)),
                )
                frontier += 1
            completed = self.completed_count + sum(self.pending.values())
            self.connection.execute(
                """UPDATE search_runs SET frontier=?, completed_candidates=?, heartbeat=?
                   WHERE fingerprint=? AND lease_token=?""",
                (str(frontier), str(completed), time.time(), self.fingerprint, self.token),
            )
            self.connection.execute("COMMIT")
            self.frontier = frontier
            self.completed_count = completed
            self.completed_out_of_order = frozenset(
                int(item[0])
                for item in self.connection.execute(
                    "SELECT batch_id FROM completed_out_of_order WHERE fingerprint=?",
                    (self.fingerprint,),
                )
            )
            self.pending.clear()
            self.last_flush = time.monotonic()
            self.last_heartbeat = self.last_flush
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def maybe_flush(self, interval: float) -> None:
        now = time.monotonic()
        if len(self.pending) >= 100 or (self.pending and now - self.last_flush >= interval):
            self.flush()
        elif self.has_lease and now - self.last_heartbeat >= 5:
            self.connection.execute(
                "UPDATE search_runs SET heartbeat=? WHERE fingerprint=? AND lease_token=?",
                (time.time(), self.fingerprint, self.token),
            )
            self.last_heartbeat = now

    def finish(
        self,
        status: Literal["found", "exhausted"],
        layout_id: int | None = None,
        assignment_index: int | None = None,
        found_tested_count: int = 0,
    ) -> None:
        self.flush()
        self.connection.execute(
            """UPDATE search_runs SET status=?, found_layout_id=?,
               found_assignment_index=?, completed_candidates=?, lease_host=NULL,
               lease_pid=NULL, lease_token=NULL, heartbeat=NULL
               WHERE fingerprint=? AND lease_token=?""",
            (
                status,
                str(layout_id) if layout_id is not None else None,
                str(assignment_index) if assignment_index is not None else None,
                str(self.completed_count + found_tested_count),
                self.fingerprint,
                self.token,
            ),
        )
        self.has_lease = False

    def close(self) -> None:
        try:
            if self.has_lease:
                self.flush()
                self.connection.execute(
                    """UPDATE search_runs SET lease_host=NULL, lease_pid=NULL,
                       lease_token=NULL, heartbeat=NULL
                       WHERE fingerprint=? AND lease_token=?""",
                    (self.fingerprint, self.token),
                )
                self.has_lease = False
        finally:
            self.connection.close()


def find_missing_private_key(
    key_spec: str | tuple[str, str],
    target_address: str,
    *,
    mode: SearchMode = "pattern",
    workers: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_candidates: int | None = DEFAULT_MAX_CANDIDATES,
    force: bool = False,
    show_progress: bool = True,
    progress_interval: float = 1.0,
    progress_callback: ProgressCallback | None = None,
    checkpoint_path: str | Path | None = None,
    checkpoint_interval: float = DEFAULT_CHECKPOINT_INTERVAL,
    restart: bool = False,
) -> str | None:
    """Search for a private key matching ``target_address``.

    ``max_candidates`` is a guard against accidentally starting an impractically
    large search. Set ``force=True`` to explicitly bypass it.
    """
    spec = build_search_spec(key_spec, mode)
    target_bytes = normalize_address(target_address)

    if batch_size <= 0:
        raise ValueError("Batch size must be greater than zero.")
    if workers is not None and workers <= 0:
        raise ValueError("Worker count must be greater than zero.")
    if progress_interval < 0:
        raise ValueError("Progress interval cannot be negative.")
    if not math.isfinite(checkpoint_interval) or checkpoint_interval <= 0:
        raise ValueError("Checkpoint interval must be greater than zero.")
    if restart and checkpoint_path is None:
        raise ValueError("Restart requires an enabled checkpoint.")
    if max_candidates is not None and max_candidates <= 0:
        raise ValueError("Maximum candidate count must be greater than zero.")
    if (
        max_candidates is not None
        and spec.total_candidates > max_candidates
        and not force
    ):
        raise ValueError(
            f"Search requires {spec.total_candidates:,} candidates, exceeding the "
            f"configured limit of {max_candidates:,}. Pass force=True in Python "
            "or --force on the CLI to continue."
        )

    combinations_per_layout = 16**spec.missing_count
    batches_per_layout = math.ceil(combinations_per_layout / batch_size)
    total_batches = spec.layout_count * batches_per_layout
    worker_count = min(workers or multiprocessing.cpu_count(), max(total_batches, 1))
    checkpoint = (
        CheckpointStore(checkpoint_path, spec, target_bytes, batch_size, total_batches, restart)
        if checkpoint_path is not None else None
    )
    if checkpoint is not None and checkpoint.status == "found":
        try:
            if checkpoint.found_layout_id is None or checkpoint.found_assignment_index is None:
                raise RuntimeError("Checkpoint has incomplete found metadata.")
            found = fill_pattern(
                pattern_for_layout(spec, checkpoint.found_layout_id),
                checkpoint.found_assignment_index,
            )
            if private_key_to_address(found) != target_bytes:
                raise RuntimeError("Checkpoint found metadata does not match the address.")
            return found
        finally:
            checkpoint.close()
    if checkpoint is not None and checkpoint.status == "exhausted":
        checkpoint.close()
        return None

    initial_completed = checkpoint.completed_count if checkpoint else 0
    completed = initial_completed
    batches = iter_work_batches(
        spec,
        batch_size,
        start_batch_id=checkpoint.frontier if checkpoint else 0,
        completed_batch_ids=checkpoint.completed_out_of_order if checkpoint else frozenset(),
    )
    start_time = time.monotonic()
    last_progress_time = start_time

    if show_progress:
        print(
            f"Mode: {spec.mode} | Missing: {spec.missing_count} | "
            f"Candidates: {spec.total_candidates:,} | Workers: {worker_count}"
        )
        if initial_completed:
            print(
                f"Resuming: {checkpoint.frontier:,}/{total_batches:,} contiguous batches; "
                f"{initial_completed:,} candidates completed "
                f"({initial_completed / spec.total_candidates * 100:.2f}%); "
                f"{spec.total_candidates - initial_completed:,} candidates remain."
            )

    def report_progress(*, final: bool = False) -> None:
        nonlocal completed, last_progress_time
        snapshot = _make_progress(
            completed, spec.total_candidates, start_time, initial_completed
        )
        if progress_callback is not None:
            progress_callback(snapshot)

        now = time.monotonic()
        search_finished = final or completed == spec.total_candidates
        if show_progress and (
            search_finished or now - last_progress_time >= progress_interval
        ):
            print(_format_progress(snapshot))
            last_progress_time = now

    try:
        if worker_count == 1:
            stop_event: Any = threading.Event()
            _init_worker(target_bytes, stop_event)
            executor: concurrent.futures.Executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1
            )
        else:
            context = multiprocessing.get_context("spawn")
            stop_event = context.Event()
            executor = concurrent.futures.ProcessPoolExecutor(
                max_workers=worker_count,
                mp_context=context,
                initializer=_init_worker,
                initargs=(target_bytes, stop_event),
            )
    except BaseException:
        if checkpoint is not None:
            checkpoint.close()
        raise

    in_flight: dict[concurrent.futures.Future[BatchResult], WorkBatch] = {}
    found_result: tuple[WorkBatch, BatchResult] | None = None
    error: BaseException | None = None

    def record(batch: WorkBatch, result: BatchResult, *, notify: bool) -> None:
        nonlocal completed, found_result
        if result.batch_id != batch.batch_id:
            raise RuntimeError("Worker returned a mismatched batch ID.")
        if result.found_assignment_index is not None:
            if not batch.start <= result.found_assignment_index < batch.stop:
                raise RuntimeError("Worker returned an invalid assignment index.")
            if result.found_key != fill_pattern(batch.pattern, result.found_assignment_index):
                raise RuntimeError("Worker returned inconsistent found metadata.")
            if found_result is None:
                found_result = (batch, result)
                completed += result.tested_count
            stop_event.set()
        elif result.tested_count == batch.stop - batch.start:
            completed += result.tested_count
            if checkpoint is not None:
                checkpoint.add_completed(batch.batch_id, result.tested_count)
        elif not stop_event.is_set():
            raise RuntimeError("Worker stopped before completing its batch.")
        if notify:
            report_progress(final=found_result is not None)

    def fill_capacity() -> None:
        while len(in_flight) < worker_count * 2 and not stop_event.is_set():
            try:
                batch = next(batches)
            except StopIteration:
                break
            in_flight[executor.submit(search_batch, batch)] = batch

    try:
        fill_capacity()
        while in_flight and found_result is None:
            done, _ = concurrent.futures.wait(
                in_flight,
                timeout=1,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                batch = in_flight.pop(future)
                record(batch, future.result(), notify=True)
            if checkpoint is not None:
                checkpoint.maybe_flush(checkpoint_interval)
            fill_capacity()
    except BaseException as exc:
        error = exc
    finally:
        stop_event.set()
        for future in in_flight:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        for future, batch in in_flight.items():
            if not future.cancelled():
                try:
                    record(batch, future.result(), notify=False)
                except BaseException as exc:
                    if error is None and found_result is None:
                        error = exc
        try:
            if checkpoint is not None:
                if error is None and found_result is not None:
                    batch, result = found_result
                    checkpoint.finish(
                        "found", batch.layout_id, result.found_assignment_index,
                        result.tested_count,
                    )
                elif error is None:
                    checkpoint.finish("exhausted")
                else:
                    checkpoint.flush()
                checkpoint.close()
        except BaseException as exc:
            if checkpoint is not None:
                checkpoint.connection.close()
            if error is None:
                error = exc

    if error is not None:
        raise error
    if found_result is not None:
        batch, result = found_result
        return fill_pattern(batch.pattern, result.found_assignment_index)
    if initial_completed == spec.total_candidates:
        report_progress(final=True)
    return None


def find_two_block_private_key(
    block_a: str,
    block_b: str,
    target_address: str,
    **options: Any,
) -> str | None:
    """Recover a key containing both intact blocks in either order."""
    return find_missing_private_key(
        (block_a, block_b), target_address, mode="two_blocks", **options
    )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover an EVM private key with missing hexadecimal characters."
    )
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument(
        "--pattern",
        help="A 64-character private key pattern using '?' for each missing character.",
    )
    key_group.add_argument(
        "--fragment",
        help="A contiguous private-key fragment whose offset is unknown.",
    )
    key_group.add_argument(
        "--sequence",
        help=(
            "All surviving private-key characters in their original order; "
            "missing positions are unknown."
        ),
    )
    key_group.add_argument(
        "--two-blocks", nargs=2, metavar=("BLOCK_A", "BLOCK_B"),
        help="Two intact hexadecimal blocks, in either order, with unknown gaps.",
    )
    parser.add_argument("--address", help="Target EVM address, with or without 0x.")
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument(
        "--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow a search larger than --max-candidates.",
    )
    parser.add_argument("--quiet", action="store_true", help="Disable progress output.")
    checkpoint_group = parser.add_mutually_exclusive_group()
    checkpoint_group.add_argument(
        "--checkpoint", type=Path, default=DEFAULT_CHECKPOINT_PATH,
        help="SQLite checkpoint path (enabled by default).",
    )
    checkpoint_group.add_argument(
        "--no-checkpoint", action="store_true", help="Do not save progress.",
    )
    parser.add_argument(
        "--checkpoint-interval", type=float, default=DEFAULT_CHECKPOINT_INTERVAL,
        metavar="SECONDS", help="Maximum time between checkpoint writes (default: 5).",
    )
    parser.add_argument(
        "--restart", action="store_true", help="Discard this search's saved progress.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    if args.two_blocks is not None:
        key_spec: str | tuple[str, str] = tuple(args.two_blocks)
        mode: SearchMode = "two_blocks"
    elif args.pattern is not None:
        key_spec = args.pattern
        mode = "pattern"
    elif args.fragment is not None:
        key_spec = args.fragment
        mode = "fragment"
    elif args.sequence is not None:
        key_spec = args.sequence
        mode = "sequence"
    else:
        key_spec = DEFAULT_FRAGMENT
        mode = "fragment"

    if (
        args.pattern is not None
        or args.fragment is not None
        or args.sequence is not None
        or args.two_blocks is not None
    ) and args.address is None:
        parser.error(
            "--address is required when --pattern, --fragment, --sequence, or --two-blocks "
            "is supplied."
        )
    if args.restart and args.no_checkpoint:
        parser.error("--restart cannot be combined with --no-checkpoint.")
    target_address = args.address or DEFAULT_TARGET_ADDRESS

    started = time.monotonic()
    try:
        found_key = find_missing_private_key(
            key_spec,
            target_address,
            mode=mode,
            workers=args.workers,
            batch_size=args.batch_size,
            max_candidates=args.max_candidates,
            force=args.force,
            show_progress=not args.quiet,
            checkpoint_path=None if args.no_checkpoint else args.checkpoint,
            checkpoint_interval=args.checkpoint_interval,
            restart=args.restart,
        )
    except (TypeError, ValueError, RuntimeError, sqlite3.Error, OSError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("\nSearch cancelled.")
        return 130

    if found_key is not None:
        print(f"Found private key: {found_key}")
    else:
        print("No matching private key found.")
    print(f"Total running time: {time.monotonic() - started:.2f}s")
    return 0 if found_key is not None else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
