"""Code analysis endpoint implementation."""

from fastapi import APIRouter, Depends, HTTPException, status

from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.api.dependencies import check_rate_limit, get_api_settings, get_engine
from bug_detector.core.config import Settings
from bug_detector.core.models import AnalysisRequest, AnalysisResult

router = APIRouter(prefix="/api", tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=AnalysisResult,
    dependencies=[Depends(check_rate_limit)],
    summary="Analyze Python source code",
)
def analyze_code(
    payload: AnalysisRequest,
    engine: AnalysisEngine = Depends(get_engine),
    settings: Settings = Depends(get_api_settings),
) -> AnalysisResult:
    """Perform zero-execution AST-based static bug detection on submitted Python code.

    Guarantees:
    - User code is NEVER executed or evaluated.
    - Size and line constraints are strictly enforced before parsing.
    - If DEMO_MODE is active, code is not saved to repository and paid AI is skipped.
    """
    raw_bytes = len(payload.source_code.encode("utf-8"))
    if raw_bytes > settings.max_code_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"Source code payload ({raw_bytes} bytes) exceeds maximum "
                f"allowed limit ({settings.max_code_size_bytes} bytes)."
            ),
        )

    line_count = len(payload.source_code.splitlines())
    if line_count > settings.max_code_lines:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Source code line count ({line_count}) exceeds maximum "
                f"allowed limit ({settings.max_code_lines} lines)."
            ),
        )

    try:
        return engine.analyze(payload, save=True)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from None
