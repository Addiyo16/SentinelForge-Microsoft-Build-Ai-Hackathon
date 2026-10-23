"""
Unit tests for SentinelForge Async Pipeline DAG Scheduler.
Tests dependency ordering, concurrency, and execution state handling.
"""

import pytest
import asyncio
from app.structures.dag import PipelineDAG, StageStatus


class TestPipelineDAG:
    @pytest.mark.asyncio
    async def test_sequential_dependency_execution(self):
        dag = PipelineDAG()
        order = []

        async def stage_a(state):
            await asyncio.sleep(0.05)
            order.append("A")
            return {"val": 1}

        async def stage_b(state):
            await asyncio.sleep(0.05)
            order.append("B")
            return {"val": 2}

        dag.add_stage("A", stage_a)
        dag.add_stage("B", stage_b, depends_on=["A"])

        state = await dag.run({})
        assert order == ["A", "B"]
        assert dag.stages["A"].status == StageStatus.COMPLETE
        assert dag.stages["B"].status == StageStatus.COMPLETE

    @pytest.mark.asyncio
    async def test_parallel_independent_stages(self):
        dag = PipelineDAG()
        completed = []

        async def stage_p1(state):
            await asyncio.sleep(0.05)
            completed.append("P1")

        async def stage_p2(state):
            await asyncio.sleep(0.05)
            completed.append("P2")

        dag.add_stage("P1", stage_p1)
        dag.add_stage("P2", stage_p2)

        await dag.run({})
        assert set(completed) == {"P1", "P2"}
        assert dag.stages["P1"].status == StageStatus.COMPLETE
        assert dag.stages["P2"].status == StageStatus.COMPLETE

    @pytest.mark.asyncio
    async def test_failure_skips_dependent_stages(self):
        dag = PipelineDAG()

        async def stage_fail(state):
            raise ValueError("Deliberate failure in root stage")

        async def stage_dependent(state):
            pass

        dag.add_stage("Root", stage_fail)
        dag.add_stage("Child", stage_dependent, depends_on=["Root"])

        results = await dag.run({})

        assert dag.stages["Root"].status == StageStatus.FAILED
        assert "Deliberate failure" in dag.stages["Root"].error
        assert dag.stages["Child"].status == StageStatus.SKIPPED
