"""Worker-graph node implementations.

Split out of `workflows/worker_graph.py` (split-worker-graph run, 2026-04-26).
The StateGraph wiring + routing functions remain in `worker_graph.py`; each
module here owns one cohesive group of nodes plus their tightly-scoped
helpers and constants.

The string names registered via `workflow.add_node(...)` in
`worker_graph.py` are part of the LangGraph checkpointer's on-disk
contract — in-flight scans key off them.
"""
