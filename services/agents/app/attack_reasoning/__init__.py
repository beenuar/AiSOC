"""
MITRE ATT&CK-based Attack Reasoning System
==========================================

This module implements a LangGraph-based multi-agent system that reasons about 
attacks using the MITRE ATT&CK framework as its foundation.

The system consists of specialized agents that:
1. Analyze attack patterns using MITRE ATT&CK techniques
2. Identify potential attack paths through the kill chain
3. Recommend mitigations based on ATT&CK mitigations
4. Map observed indicators to specific threat actors
5. Provide tactical recommendations grounded in ATT&CK

AiSOC — open-source AI Security Operations Center (MIT License)
"""