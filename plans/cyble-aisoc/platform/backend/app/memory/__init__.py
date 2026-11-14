"""Memory subsystems: scratchpad (Redis), episodic (Qdrant), threat graph (Neo4j)."""
from app.memory.scratchpad import scratchpad  # noqa: F401
from app.memory.episodic import (  # noqa: F401
    episodic_backend_name,
    episodic_recall,
    episodic_record,
)
from app.memory.embedding import embed  # noqa: F401
from app.memory.graph import (  # noqa: F401
    graph_backend_name,
    graph_find_nodes,
    graph_neighbors,
    graph_upsert_edge,
    graph_upsert_node,
)
from app.memory.autopop import (  # noqa: F401
    populate_from_alert,
    populate_from_ioc,
)
from app.memory.detection_kb import (  # noqa: F401
    DetectionKB,
    DetectionMatch,
    detection_by_id,
    detection_count,
    detection_kb_backend_name,
    detection_search,
    get_detection_kb,
    reset_detection_kb,
)
