"""
MMR Reranking Engine
====================
Pure function — no Qdrant dependency.
Accepts scored Qdrant points and returns MMR-reranked subset.

MMR Formula:
  score = λ * sim(d, query) - (1-λ) * max(sim(d, s) for s in selected)

λ values by collection:
  - playbooks:           0.7  (relevance-heavy, prevents clone playbooks)
  - historical_incidents: 0.6 (more diversity, learn from varied patterns)
  - d3fend fallback:     0.6  (want diverse Harden/Detect/Isolate mix)
"""

from typing import Any, Dict, List, Optional
import numpy as np


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two L2-normalized or unnormalized vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def mmr_rerank(
    query_embedding: np.ndarray,
    candidates: List[Dict[str, Any]],
    k: int = 5,
    lambda_param: float = 0.7,
    embedding_key: str = "vector",
    score_key: str = "score",
) -> List[Dict[str, Any]]:
    """
    Maximum Marginal Relevance reranking.

    Args:
        query_embedding: Query vector (1D numpy array)
        candidates: List of dicts, each must have:
                    - embedding_key: the vector (list or np.ndarray)
                    - score_key: original similarity score (float)
                    - plus any payload fields
        k: Number of results to return
        lambda_param: Balance between relevance (1.0) and diversity (0.0)
        embedding_key: Key in candidate dict holding the vector
        score_key: Key holding the original relevance score

    Returns:
        Top-k candidates reranked by MMR score
    """
    if not candidates:
        return []

    k = min(k, len(candidates))
    query_emb = np.array(query_embedding, dtype=np.float32)

    # Pre-compute similarity of each candidate to the query
    item_embeddings = [
        np.array(c[embedding_key], dtype=np.float32) for c in candidates
    ]
    query_sims = [cosine_similarity(query_emb, emb) for emb in item_embeddings]

    selected_indices: List[int] = []
    selected_embeddings: List[np.ndarray] = []
    remaining_indices = list(range(len(candidates)))

    for _ in range(k):
        best_idx: Optional[int] = None
        best_mmr: float = float("-inf")

        for idx in remaining_indices:
            relevance = query_sims[idx]

            if not selected_embeddings:
                diversity_penalty = 0.0
            else:
                max_sim_to_selected = max(
                    cosine_similarity(item_embeddings[idx], sel_emb)
                    for sel_emb in selected_embeddings
                )
                diversity_penalty = max_sim_to_selected

            mmr_score = lambda_param * relevance - (1 - lambda_param) * diversity_penalty

            if mmr_score > best_mmr:
                best_mmr = mmr_score
                best_idx = idx

        if best_idx is None:
            break

        # Annotate with mmr_score and mark selected
        result = dict(candidates[best_idx])
        result["mmr_score"] = round(best_mmr, 4)
        result["original_score"] = round(query_sims[best_idx], 4)

        selected_indices.append(best_idx)
        selected_embeddings.append(item_embeddings[best_idx])
        remaining_indices.remove(best_idx)

    return [
        dict(candidates[i], mmr_score=round(
            lambda_param * query_sims[i] - 0, 4  # mmr_score already set above
        ))
        for i in selected_indices
    ]


def mmr_rerank_qdrant(
    query_embedding: np.ndarray,
    scored_points: List[Any],           # qdrant_client ScoredPoint list
    k: int = 5,
    lambda_param: float = 0.7,
) -> List[Any]:
    """
    MMR reranking directly on Qdrant ScoredPoint objects.
    Qdrant must be queried with `with_vectors=True` for this to work.

    Returns:
        Reranked list of ScoredPoint (original objects, with .score updated to mmr_score)
    """
    if not scored_points:
        return []

    k = min(k, len(scored_points))
    query_emb = np.array(query_embedding, dtype=np.float32)

    # Extract embeddings from ScoredPoints
    embeddings = []
    for pt in scored_points:
        vec = pt.vector
        if isinstance(vec, dict):
            # Named vectors — take first
            vec = next(iter(vec.values()))
        embeddings.append(np.array(vec, dtype=np.float32))

    query_sims = [cosine_similarity(query_emb, emb) for emb in embeddings]

    selected_indices: List[int] = []
    selected_embeddings: List[np.ndarray] = []
    remaining = list(range(len(scored_points)))
    selected_points: List[Any] = []

    for _ in range(k):
        best_idx: Optional[int] = None
        best_mmr: float = float("-inf")

        for idx in remaining:
            relevance = query_sims[idx]
            if not selected_embeddings:
                diversity_penalty = 0.0
            else:
                diversity_penalty = max(
                    cosine_similarity(embeddings[idx], s) for s in selected_embeddings
                )
            mmr = lambda_param * relevance - (1 - lambda_param) * diversity_penalty
            if mmr > best_mmr:
                best_mmr = mmr
                best_idx = idx

        if best_idx is None:
            break

        pt = scored_points[best_idx]
        # Mutate score to reflect MMR score so downstream code sees it
        pt.score = round(best_mmr, 4)
        selected_points.append(pt)
        selected_indices.append(best_idx)
        selected_embeddings.append(embeddings[best_idx])
        remaining.remove(best_idx)

    return selected_points
