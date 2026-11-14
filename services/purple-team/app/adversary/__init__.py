"""Self-play purple team (v8 P2).

Turns the purple-team service from a test runner into a continuous adversary:
an LLM-planned campaign engine composes multi-stage attack chains from the
Atomic Red Team + Caldera inventory, runs them in a closed loop against the live
defense, scores detected/missed per technique, and auto-files Detection-as-Code
proposals for every miss — all constrained to an allowlisted lab scope by a hard
code guard (never a prompt instruction).
"""
