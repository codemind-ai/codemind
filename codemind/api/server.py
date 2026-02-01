"""CodeMind REST API Server.

Exposes CodeMind functionality via a standard REST API.
"""

import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

from ..git.diff import get_diff
from ..git.context import get_context
from ..prompt.builder import build_prompt, PromptConfig
from ..llm import get_llm_provider
from ..cli.config import load_config
from ..history import get_recent_reviews, get_review_stats

app = FastAPI(
    title="CodeMind AI API",
    description="Programmatic access to AI code reviews and git intelligence.",
    version="0.1.0"
)


class ReviewRequest(BaseModel):
    base: Optional[str] = None
    max_comments: int = 5
    vibe: bool = False
    provider: Optional[str] = None


class ReviewResult(BaseModel):
    success: bool
    branch: str
    files_changed: int
    review: Optional[str] = None
    error: Optional[str] = None


@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Think before ship. CodeMind API is active.",
        "version": "0.1.0"
    }


@app.get("/v1/stats")
async def get_stats():
    """Get project-wide review statistics."""
    try:
        return get_review_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/history")
async def get_history(limit: int = 10):
    """Retrieve recent review history."""
    try:
        reviews = get_recent_reviews(limit)
        return reviews
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/review", response_model=ReviewResult)
async def trigger_review(request: ReviewRequest):
    """Trigger a new AI code review for the current changes."""
    try:
        config = load_config()
        context = get_context()
        diff = get_diff(base=request.base)
        
        if diff.is_empty:
            return ReviewResult(
                success=False,
                branch=context.current_branch,
                files_changed=0,
                error="No changes detected"
            )
            
        # Select provider
        provider_type = request.provider or config.llm.provider
        if provider_type == "ide":
            # API cannot easily talk to IDE AI, fallback to OpenAI if not set
            provider_type = "openai"
        
        # Build prompt
        prompt_config = PromptConfig(max_comments=request.max_comments)
        built = build_prompt(diff, context, prompt_config)
        
        # Run review
        llm = get_llm_provider(
            provider_type=provider_type,
            model=config.llm.model,
            api_key=config.llm.api_key,
            base_url=config.llm.base_url
        )
        
        response = llm.generate(built.content)
        
        return ReviewResult(
            success=True,
            branch=context.current_branch,
            files_changed=built.file_count,
            review=response.content
        )
        
    except Exception as e:
        return ReviewResult(
            success=False,
            branch="unknown",
            files_changed=0,
            error=str(e)
        )
