"""Review history API endpoint implementations."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from bug_detector.api.dependencies import get_api_settings, get_repository
from bug_detector.core.config import Settings
from bug_detector.core.models import AnalysisHistoryItem, AnalysisResult
from bug_detector.storage.repository import ReviewRepository

router = APIRouter(prefix="/api/history", tags=["History"])


def _check_demo_mode_access(settings: Settings) -> None:
    """Security guardrail: block history operations in public demo mode."""
    if settings.demo_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="History access is disabled in public demo mode.",
        )


@router.get(
    "",
    response_model=List[AnalysisHistoryItem],
    summary="List recent review history",
)
def list_history(
    limit: int = Query(default=50, ge=1, le=200, description="Max records to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    settings: Settings = Depends(get_api_settings),
    repository: Optional[ReviewRepository] = Depends(get_repository),
) -> List[AnalysisHistoryItem]:
    """Retrieve paginated historical review summaries ordered newest first."""
    _check_demo_mode_access(settings)
    if repository is None:
        return []
    return repository.list_recent_reviews(limit=limit, offset=offset)


@router.get(
    "/{review_id}",
    response_model=AnalysisResult,
    summary="Get complete review details by ID",
)
def get_history_detail(
    review_id: str,
    settings: Settings = Depends(get_api_settings),
    repository: Optional[ReviewRepository] = Depends(get_repository),
) -> AnalysisResult:
    """Retrieve full AnalysisResult by review UUID."""
    _check_demo_mode_access(settings)
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' not found.",
        )
    review = repository.get_review_by_id(review_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' not found.",
        )
    return review


@router.delete(
    "/{review_id}",
    summary="Delete a single review record",
)
def delete_history_item(
    review_id: str,
    settings: Settings = Depends(get_api_settings),
    repository: Optional[ReviewRepository] = Depends(get_repository),
) -> Dict[str, Any]:
    """Delete a specific review by UUID."""
    _check_demo_mode_access(settings)
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' not found.",
        )
    deleted = repository.delete_review(review_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' not found.",
        )
    return {"deleted": True, "review_id": review_id}


@router.post(
    "/clear",
    summary="Clear all review history",
)
def clear_all_history(
    settings: Settings = Depends(get_api_settings),
    repository: Optional[ReviewRepository] = Depends(get_repository),
) -> Dict[str, Any]:
    """Permanently delete all historical review records."""
    _check_demo_mode_access(settings)
    if repository is None:
        return {"cleared_count": 0}
    count = repository.clear_history()
    return {"cleared_count": count}
