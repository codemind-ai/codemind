"""CodeMind Documentation Fetcher - Built-in Context7 API integration.

Provides up-to-date, version-specific documentation for any library directly
within CodeMind, similar to Context7 MCP.
"""

import re
from dataclasses import dataclass
from typing import Optional, List
from urllib.parse import quote

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# Context7 API configuration
CONTEXT7_API_BASE = "https://api.context7.com"
CONTEXT7_SEARCH_ENDPOINT = "/v1/search"
CONTEXT7_CONTEXT_ENDPOINT = "/api/v2/context"

# Common library mappings for quick resolution
LIBRARY_ALIASES = {
    # Frontend Frameworks
    "react": "/facebook/react",
    "nextjs": "/vercel/next.js",
    "next": "/vercel/next.js",
    "vue": "/vuejs/vue",
    "nuxt": "/nuxt/nuxt",
    "angular": "/angular/angular",
    "svelte": "/sveltejs/svelte",
    "sveltekit": "/sveltejs/kit",
    "solid": "/solidjs/solid",
    "qwik": "/BuilderIO/qwik",
    "remix": "/remix-run/remix",
    "gatsby": "/gatsbyjs/gatsby",
    "astro": "/withastro/astro",
    
    # Backend Frameworks - Python
    "fastapi": "/tiangolo/fastapi",
    "django": "/django/django",
    "flask": "/pallets/flask",
    "starlette": "/encode/starlette",
    "sanic": "/sanic-org/sanic",
    "tornado": "/tornadoweb/tornado",
    "aiohttp": "/aio-libs/aiohttp",
    "litestar": "/litestar-org/litestar",
    
    # Backend Frameworks - Node.js
    "express": "/expressjs/express",
    "fastify": "/fastify/fastify",
    "nestjs": "/nestjs/nest",
    "hono": "/honojs/hono",
    "koa": "/koajs/koa",
    "hapi": "/hapijs/hapi",
    
    # Languages & Runtimes
    "typescript": "/microsoft/typescript",
    "python": "/python/cpython",
    "node": "/nodejs/node",
    "nodejs": "/nodejs/node",
    "deno": "/denoland/deno",
    "bun": "/oven-sh/bun",
    "rust": "/rust-lang/rust",
    "go": "/golang/go",
    
    # Databases & ORMs
    "prisma": "/prisma/prisma",
    "drizzle": "/drizzle-team/drizzle-orm",
    "mongodb": "/mongodb/docs",
    "postgres": "/postgres/postgres",
    "postgresql": "/postgres/postgres",
    "mysql": "/mysql/mysql-server",
    "supabase": "/supabase/supabase",
    "redis": "/redis/redis",
    "sqlite": "/sqlite/sqlite",
    "sqlalchemy": "/sqlalchemy/sqlalchemy",
    "asyncpg": "/MagicStack/asyncpg",
    "typeorm": "/typeorm/typeorm",
    "sequelize": "/sequelize/sequelize",
    "mongoose": "/Automattic/mongoose",
    
    # Authentication & Security
    "nextauth": "/nextauthjs/next-auth",
    "authjs": "/nextauthjs/next-auth",
    "clerk": "/clerk/clerk-docs",
    "passport": "/jaredhanson/passport",
    "jwt": "/auth0/node-jsonwebtoken",
    
    # State Management & Data Fetching
    "tanstack-query": "/TanStack/query",
    "react-query": "/TanStack/query",
    "zustand": "/pmndrs/zustand",
    "jotai": "/pmndrs/jotai",
    "redux": "/reduxjs/redux",
    "swr": "/vercel/swr",
    "trpc": "/trpc/trpc",
    
    # UI Libraries & Styling
    "tailwind": "/tailwindlabs/tailwindcss",
    "tailwindcss": "/tailwindlabs/tailwindcss",
    "shadcn": "/shadcn-ui/ui",
    "radix": "/radix-ui/primitives",
    "chakra": "/chakra-ui/chakra-ui",
    "mui": "/mui/material-ui",
    "antd": "/ant-design/ant-design",
    "mantine": "/mantinedev/mantine",
    
    # Testing
    "pytest": "/pytest-dev/pytest",
    "jest": "/jestjs/jest",
    "vitest": "/vitest-dev/vitest",
    "playwright": "/microsoft/playwright",
    "cypress": "/cypress-io/cypress",
    "selenium": "/SeleniumHQ/selenium",
    
    # DevOps & Infrastructure
    "docker": "/docker/docs",
    "kubernetes": "/kubernetes/kubernetes",
    "terraform": "/hashicorp/terraform",
    "github-actions": "/actions/toolkit",
    
    # HTTP & API Clients
    "axios": "/axios/axios",
    "httpx": "/encode/httpx",
    "requests": "/psf/requests",
    "fetch": "/node-fetch/node-fetch",
    
    # Utilities
    "lodash": "/lodash/lodash",
    "zod": "/colinhacks/zod",
    "pydantic": "/pydantic/pydantic",
    "git": "/git/git",
    "celery": "/celery/celery",
    
    # AI & ML
    "langchain": "/langchain-ai/langchain",
    "openai": "/openai/openai-python",
    "anthropic": "/anthropics/anthropic-sdk-python",
    "transformers": "/huggingface/transformers",
    "pytorch": "/pytorch/pytorch",
    "tensorflow": "/tensorflow/tensorflow",
    "numpy": "/numpy/numpy",
    "pandas": "/pandas-dev/pandas",
    "scikit-learn": "/scikit-learn/scikit-learn",
}


@dataclass
class LibraryInfo:
    """Information about a resolved library."""
    library_id: str
    name: str
    description: str
    snippet_count: int = 0
    
    
@dataclass
class DocumentationResult:
    """Result of a documentation query."""
    library_id: str
    query: str
    content: str
    source_url: Optional[str] = None
    success: bool = True
    error: Optional[str] = None


class DocumentationFetcher:
    """Fetches up-to-date documentation from Context7 API."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        if not HAS_HTTPX:
            raise ImportError(
                "httpx is required for documentation fetching. "
                "Install with: pip install httpx"
            )
        self.client = httpx.Client(timeout=30.0)
    
    def _get_headers(self) -> dict:
        """Get request headers with optional API key."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CodeMind-MCP/1.0"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    def resolve_library(self, name: str) -> Optional[LibraryInfo]:
        """
        Resolve a library name to a Context7-compatible library ID.
        
        Args:
            name: Library name to search for (e.g., "react", "next.js")
            
        Returns:
            LibraryInfo with the resolved library ID, or None if not found
        """
        # Check aliases first for common libraries
        normalized = name.lower().strip().replace(".", "").replace("-", "")
        if normalized in LIBRARY_ALIASES:
            return LibraryInfo(
                library_id=LIBRARY_ALIASES[normalized],
                name=name,
                description=f"Documentation for {name}"
            )
        
        # Try to search via Context7 API
        try:
            url = f"{CONTEXT7_API_BASE}{CONTEXT7_SEARCH_ENDPOINT}"
            response = self.client.get(
                url,
                params={"q": name},
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("results") and len(data["results"]) > 0:
                    first = data["results"][0]
                    return LibraryInfo(
                        library_id=first.get("id", f"/{name}"),
                        name=first.get("name", name),
                        description=first.get("description", ""),
                        snippet_count=first.get("snippetCount", 0)
                    )
        except Exception:
            pass
        
        # Fallback: construct a reasonable library ID
        # Format: /org/project based on common patterns
        if "/" in name:
            return LibraryInfo(
                library_id=f"/{name}" if not name.startswith("/") else name,
                name=name,
                description=f"Documentation for {name}"
            )
        
        return None
    
    def query_docs(
        self, 
        library_id: str, 
        query: str,
        max_tokens: int = 5000
    ) -> DocumentationResult:
        """
        Fetch documentation for a specific query.
        
        Args:
            library_id: Context7-compatible library ID (e.g., "/facebook/react")
            query: The question or topic to get documentation for
            max_tokens: Maximum tokens in response (default: 5000)
            
        Returns:
            DocumentationResult with the fetched content
        """
        try:
            url = f"{CONTEXT7_API_BASE}{CONTEXT7_CONTEXT_ENDPOINT}"
            response = self.client.get(
                url,
                params={
                    "libraryId": library_id,
                    "query": query,
                    "maxTokens": max_tokens
                },
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data.get("context", data.get("content", ""))
                
                if content:
                    return DocumentationResult(
                        library_id=library_id,
                        query=query,
                        content=content,
                        source_url=data.get("sourceUrl"),
                        success=True
                    )
                else:
                    return DocumentationResult(
                        library_id=library_id,
                        query=query,
                        content="",
                        success=False,
                        error="No documentation found for this query."
                    )
            
            elif response.status_code == 404:
                return DocumentationResult(
                    library_id=library_id,
                    query=query,
                    content="",
                    success=False,
                    error=f"Library '{library_id}' not found in documentation index."
                )
            
            elif response.status_code == 429:
                return DocumentationResult(
                    library_id=library_id,
                    query=query,
                    content="",
                    success=False,
                    error="Rate limit exceeded. Try again later or use an API key."
                )
            
            else:
                return DocumentationResult(
                    library_id=library_id,
                    query=query,
                    content="",
                    success=False,
                    error=f"API error: {response.status_code}"
                )
                
        except httpx.TimeoutException:
            return DocumentationResult(
                library_id=library_id,
                query=query,
                content="",
                success=False,
                error="Request timed out. Try again."
            )
        except Exception as e:
            return DocumentationResult(
                library_id=library_id,
                query=query,
                content="",
                success=False,
                error=str(e)
            )
    
    def close(self):
        """Close the HTTP client."""
        self.client.close()


def detect_frameworks(code: str) -> List[str]:
    """
    Detect frameworks and libraries used in code.
    
    Args:
        code: Source code to analyze
        
    Returns:
        List of detected library names
    """
    detected = []
    
    patterns = [
        # Python imports
        (r"from\s+(fastapi|django|flask|pytest|numpy|pandas|requests|httpx)\b", 1),
        (r"import\s+(fastapi|django|flask|pytest|numpy|pandas|requests|httpx)\b", 1),
        
        # JavaScript/TypeScript imports
        (r"from\s+['\"]react['\"]", "react"),
        (r"from\s+['\"]next", "nextjs"),
        (r"from\s+['\"]vue['\"]", "vue"),
        (r"from\s+['\"]@angular", "angular"),
        (r"from\s+['\"]svelte['\"]", "svelte"),
        (r"from\s+['\"]express['\"]", "express"),
        (r"from\s+['\"]@prisma", "prisma"),
        (r"from\s+['\"]@supabase", "supabase"),
        
        # Common patterns
        (r"createClient\s*\(\s*\)", "supabase"),
        (r"useQuery|useMutation", "tanstack-query"),
        (r"useState|useEffect|useCallback", "react"),
        (r"@app\.(get|post|put|delete|patch)", "fastapi"),
        (r"@pytest\.fixture", "pytest"),
    ]
    
    for pattern, lib in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            lib_name = lib if isinstance(lib, str) else None
            if lib_name and lib_name not in detected:
                detected.append(lib_name)
    
    return detected


# Singleton instance for convenience
_fetcher: Optional[DocumentationFetcher] = None


def get_fetcher(api_key: Optional[str] = None) -> DocumentationFetcher:
    """Get or create a DocumentationFetcher instance."""
    global _fetcher
    if _fetcher is None:
        try:
            _fetcher = DocumentationFetcher(api_key)
        except ImportError:
            return None
    return _fetcher
