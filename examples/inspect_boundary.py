"""Replay two report files using the optional wheel-installed task."""
from inspect_ai import task
from agent_boundary_check.inspect_replay import boundary_replay as installed_task


@task
def boundary_replay(before: str, after: str, policy: str):
    return installed_task(before, after, policy)
