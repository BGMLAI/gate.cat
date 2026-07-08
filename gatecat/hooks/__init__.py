"""Agent-harness hooks shipped WITH the package (F8, eng review E1).

Keep this __init__ import-free: a hook must start in milliseconds and its
import must never be the thing that fails. Each hook module does its own
guarded engine import and fails CLOSED (exit 2) if the engine is unavailable.
"""
