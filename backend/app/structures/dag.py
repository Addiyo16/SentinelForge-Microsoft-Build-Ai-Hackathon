"""
SentinelForge — DAG Pipeline Scheduler
Manages async execution of analysis stages with dependency resolution.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Stage:
    name: str
    fn: Callable[..., Coroutine]
    depends_on: list[str] = field(default_factory=list)
    status: StageStatus = StageStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    duration_ms: Optional[float] = None


class PipelineDAG:
    """
    Directed Acyclic Graph executor.
    Stages with no unresolved dependencies run in parallel.
    """

    def __init__(self):
        self.stages: dict[str, Stage] = {}

    def add_stage(self, name: str, fn: Callable, depends_on: list[str] = None):
        self.stages[name] = Stage(name=name, fn=fn, depends_on=depends_on or [])

    def _ready_stages(self) -> list[str]:
        """Return names of stages whose dependencies are all complete."""
        ready = []
        for name, stage in self.stages.items():
            if stage.status != StageStatus.PENDING:
                continue
            deps_done = all(
                self.stages[d].status == StageStatus.COMPLETE
                for d in stage.depends_on
                if d in self.stages
            )
            if deps_done:
                ready.append(name)
        return ready

    def get_topology(self) -> list[dict]:
        """Return stage list with dependency info for UI rendering."""
        return [
            {
                "name": s.name,
                "depends_on": s.depends_on,
                "status": s.status.value,
                "duration_ms": s.duration_ms,
            }
            for s in self.stages.values()
        ]

    async def execute(self, context: dict) -> dict[str, Any]:
        """
        Execute all stages respecting dependencies.
        Parallel-eligible stages run concurrently.
        """
        results: dict[str, Any] = {}
        max_iterations = len(self.stages) * 2  # safety guard

        for _ in range(max_iterations):
            ready = self._ready_stages()
            if not ready:
                # Check if anything is still running or pending
                pending = [s for s in self.stages.values() if s.status == StageStatus.PENDING]
                if not pending:
                    break
                await asyncio.sleep(0.05)
                continue

            # Launch all ready stages in parallel
            async def run_stage(name: str):
                stage = self.stages[name]
                stage.status = StageStatus.RUNNING
                stage.started_at = time.time()
                try:
                    # Build kwargs from completed dependency results
                    dep_results = {d: results[d] for d in stage.depends_on if d in results}
                    stage.result = await stage.fn(context=context, deps=dep_results)
                    results[name] = stage.result
                    stage.status = StageStatus.COMPLETE
                except Exception as e:
                    stage.error = str(e)
                    stage.status = StageStatus.FAILED
                    results[name] = None
                finally:
                    stage.finished_at = time.time()
                    stage.duration_ms = round(
                        (stage.finished_at - stage.started_at) * 1000, 2
                    )

            await asyncio.gather(*[run_stage(n) for n in ready])

        return results


def build_sentinelforge_dag() -> PipelineDAG:
    """
    Pre-wired 6-stage SentinelForge DAG:

    [ingest] → [trie_scan] → [ast_analysis] → [rag_lookup]
                                             ↘
                                              [optimizer ‖ auditor] → [report]
    """
    dag = PipelineDAG()
    dag.add_stage("ingest",       fn=None, depends_on=[])
    dag.add_stage("trie_scan",    fn=None, depends_on=["ingest"])
    dag.add_stage("ast_analysis", fn=None, depends_on=["trie_scan"])
    dag.add_stage("rag_lookup",   fn=None, depends_on=["ast_analysis"])
    dag.add_stage("optimizer",    fn=None, depends_on=["rag_lookup"])
    dag.add_stage("auditor",      fn=None, depends_on=["rag_lookup"])
    dag.add_stage("report",       fn=None, depends_on=["optimizer", "auditor"])
    return dag
