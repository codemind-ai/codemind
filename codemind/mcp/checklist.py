"""CodeMind Launch Checklist implementation.

This module provides specialized checks and boilerplate generation for the
'Vibe Coder' launch checklist:
1. Rate limiting
2. Row Level Security (RLS)
3. CAPTCHA on auth + forms
4. Server-side validation
5. API keys secured
6. Env vars set properly
7. CORS restrictions
8. Dependency audit
9. Safety Lock (destructive actions)
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class ChecklistItem:
    id: str
    name: str
    status: str  # 'passed', 'failed', 'warning'
    message: str
    suggestion: str
    category: str

class LaunchAudit:
    def __init__(self):
        # Patterns for detecting implementation features
        self.patterns = {
            "rate_limit": [
                r"rate-?limit",
                r"Limiter\(",
                r"SlowDown",
                r"express-rate-limit",
                r"flask-limiter",
                r"fastapi-limiter"
            ],
            "rls": [
                r"ENABLE ROW LEVEL SECURITY",
                r"FOR SELECT USING",
                r"FOR INSERT WITH CHECK",
                r"supabase\.rpc\(",
                r"auth\.uid\(\)"
            ],
            "captcha": [
                r"g-recaptcha",
                r"hcaptcha",
                r"turnstile",
                r"verify.*captcha",
                r"recaptcha\.verify"
            ],
            "validation": [
                r"zod",
                r"pydantic",
                r"joi",
                r"express-validator",
                r"validate\(",
                r"Schema\(",
                r"Field\("
            ],
            "env_vars": [
                r"process\.env",
                r"os\.environ",
                r"config\(\['",
                r"dotenv",
                r"load_dotenv"
            ],
            "cors": [
                r"cors\(",
                r"Access-Control-Allow-Origin",
                r"CORSConfig",
                r"CORSMiddleware"
            ],
            "destructive": [
                r"DROP\s+(DATABASE|TABLE|SCHEMA|INDEX|COLLECTION)",
                r"DELETE\s+FROM\s+\w+\s*(?!.*\bWHERE\b)",
                r"TRUNCATE\s+(TABLE|COLLECTION)",
                r"flushall|flushdb"
            ],
            "csrf": [
                r"csrf",
                r"xsrf",
                r"SameSite=Strict",
                r"SameSite=Lax",
                r"Antiforgery"
            ],
            "brute_force": [
                r"lockout",
                r"max_attempts",
                r"delay",
                r"sleep",
                r"fail_count"
            ],
            "auth_secure": [
                r"argon2",
                r"scrypt",
                r"bcrypt",
                r"jwt\.sign",
                r"exp:",
                r"aud:",
                r"iss:"
            ]
        }

    def audit(self, code: str, filename: str = "") -> List[ChecklistItem]:
        results = []
        
        # 1. Rate Limits
        if any(re.search(p, code, re.I) for p in self.patterns["rate_limit"]):
            results.append(ChecklistItem("rate_limit", "Rate Limiting", "passed", "Detected rate limiting implementation.", "", "Protection"))
        else:
            results.append(ChecklistItem("rate_limit", "Rate Limiting", "failed", "No rate limiting detected.", "Implement express-rate-limit, fastapi-limiter, or similar middleware to prevent DDoS/Brute-force.", "Protection"))

        # 2. Row Level Security
        if any(re.search(p, code, re.I) for p in self.patterns["rls"]):
             results.append(ChecklistItem("rls", "Row Level Security", "passed", "Detected RLS patterns.", "", "Database"))
        elif filename.endswith((".sql", ".prisma", ".schema")):
             results.append(ChecklistItem("rls", "Row Level Security", "failed", "No RLS configuration found in database schema.", "Enable RLS on all tables and define policies based on user authentication.", "Database"))
        else:
             results.append(ChecklistItem("rls", "Row Level Security", "warning", "Unable to verify RLS from current file.", "Ensure RLS is enabled in your database (Supabase/PostgreSQL) if handling user data.", "Database"))

        # 3. CAPTCHA
        if any(re.search(p, code, re.I) for p in self.patterns["captcha"]):
            results.append(ChecklistItem("captcha", "CAPTCHA Protection", "passed", "Detected CAPTCHA implementation.", "", "Authentication"))
        elif "login" in code.lower() or "signup" in code.lower() or "submit" in code.lower():
            results.append(ChecklistItem("captcha", "CAPTCHA Protection", "failed", "Potential auth/form found without CAPTCHA.", "Add Turnstile or reCAPTCHA to public-facing forms to prevent bot spam.", "Authentication"))
        else:
            results.append(ChecklistItem("captcha", "CAPTCHA Protection", "warning", "No forms detected to check for CAPTCHA.", "Verify all public forms are protected by CAPTCHA.", "Authentication"))

        # 4. Server-side Validation
        if any(re.search(p, code, re.I) for p in self.patterns["validation"]):
            results.append(ChecklistItem("validation", "Server-side Validation", "passed", "Detected validation library usage.", "", "Data Integrity"))
        else:
            results.append(ChecklistItem("validation", "Server-side Validation", "failed", "No explicit server-side validation detected.", "Use Zod, Pydantic, or Joi to validate all incoming request bodies and query params.", "Data Integrity"))

        # 6. Env Vars
        if any(re.search(p, code, re.I) for p in self.patterns["env_vars"]):
             results.append(ChecklistItem("env_vars", "Environment Variables", "passed", "Using environment variables for configuration.", "", "Configuration"))
        elif re.search(r"['\"][a-zA-Z0-9_\-\.]{15,}['\"]", code): # Heuristic for hardcoded strings
             results.append(ChecklistItem("env_vars", "Environment Variables", "failed", "Possible hardcoded secrets or config detected.", "Move secrets, API keys, and environment-specific config to .env files.", "Configuration"))
        else:
              results.append(ChecklistItem("env_vars", "Environment Variables", "warning", "No environment variable usage detected.", "Ensure all sensitive values are loaded via env vars.", "Configuration"))

        # 7. CORS Restrictions
        cors_match = re.search(r"Access-Control-Allow-Origin.*[*]", code)
        if cors_match:
             results.append(ChecklistItem("cors", "CORS Restrictions", "failed", "Wildcard CORS origin detected ('*').", "Restrict Access-Control-Allow-Origin to specific trusted domains.", "Infrastructure"))
        elif any(re.search(p, code, re.I) for p in self.patterns["cors"]):
             results.append(ChecklistItem("cors", "CORS Restrictions", "passed", "CORS configuration detected.", "", "Infrastructure"))
        else:
             results.append(ChecklistItem("cors", "CORS Restrictions", "warning", "No CORS configuration found.", "Implement CORS middleware with restricted origins for better security.", "Infrastructure"))

        # 9. Safety Lock
        destructive_match = any(re.search(p, code, re.I) for p in self.patterns["destructive"])
        if destructive_match:
             results.append(ChecklistItem("safety_lock", "Safety Lock", "failed", "Destructive action detected!", "Review code for DROP, TRUNCATE, or unconditional DELETE. Ensure these are intentional.", "Safety"))
        else:
             results.append(ChecklistItem("safety_lock", "Safety Lock", "passed", "No destructive actions detected. Safety lock engaged.", "", "Safety"))

        # 10. CSRF Protection
        if any(re.search(p, code, re.I) for p in self.patterns["csrf"]):
            results.append(ChecklistItem("csrf", "CSRF Protection", "passed", "Detected CSRF protection or SameSite patterns.", "", "Protection"))
        else:
            results.append(ChecklistItem("csrf", "CSRF Protection", "failed", "No CSRF protection detected.", "Use CSRF tokens or set cookies to SameSite=Strict/Lax. X-Requested-With is NOT enough.", "Protection"))

        # 11. Brute Force Protection
        if any(re.search(p, code, re.I) for p in self.patterns["brute_force"]):
            results.append(ChecklistItem("brute_force", "Brute Force Protection", "passed", "Detected brute-force protection (lockouts/delays).", "", "Protection"))
        else:
            results.append(ChecklistItem("brute_force", "Brute Force Protection", "failed", "No brute-force protection detected.", "Implement account lockout, IP-based rate limiting, or artificial login delays.", "Protection"))

        # 12. Auth Security (Hashing/JWT)
        if any(re.search(p, code, re.I) for p in self.patterns["auth_secure"]):
            results.append(ChecklistItem("auth_secure", "Session/Auth Security", "passed", "Detected secure hashing or robust JWT configuration.", "", "Authentication"))
        else:
            results.append(ChecklistItem("auth_secure", "Session/Auth Security", "warning", "Incomplete auth security detected.", "Ensure passwords use Argon2/Scrypt and JWTs have expiration (exp), audience (aud), and issuer (iss).", "Authentication"))

        return results

@dataclass
class BoilerplateResult:
    title: str
    code: str
    description: str

def generate_secure_boilerplate(framework: str, feature: str) -> Optional[BoilerplateResult]:
    """Generates secure boilerplate for a specific framework and feature."""
    framework = framework.lower()
    feature = feature.lower()

    # Next.js Boilerplates
    if framework == "nextjs":
        if "rate_limit" in feature:
            return BoilerplateResult(
                "Upstash Ratelimit for Next.js",
                "import { Ratelimit } from '@upstash/ratelimit';\nimport { Redis } from '@upstash/redis';\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(10, '10 s'),\n});\n\nexport async function POST(req) {\n  const ip = req.ip ?? '127.0.0.1';\n  const { success } = await ratelimit.limit(ip);\n  if (!success) return new Response('Too Many Requests', { status: 429 });\n  // ... rest of logic\n}",
                "Implementation using Upstash Redis for serverless compatible rate limiting."
            )
        if "validation" in feature:
            return BoilerplateResult(
                "Zod Validation (Next.js API)",
                "import { z } from 'zod';\n\nconst schema = z.object({\n  email: z.string().email(),\n  age: z.number().min(18),\n});\n\nexport async function POST(req) {\n  const body = await req.json();\n  const validated = schema.safeParse(body);\n  if (!validated.success) {\n    return new Response(JSON.stringify(validated.error), { status: 400 });\n  }\n  // use validated.data\n}",
                "Secure input validation using the Zod library."
            )
        if "captcha" in feature:
            return BoilerplateResult(
                "Cloudflare Turnstile Verification",
                "export async function verifyTurnstile(token: string) {\n  const formData = new FormData();\n  formData.append('secret', process.env.TURNSTILE_SECRET_KEY!);\n  formData.append('response', token);\n\n  const result = await fetch(\n    'https://challenges.cloudflare.com/turnstile/v0/siteverify',\n    { body: formData, method: 'POST' }\n  );\n  const outcome = await result.json();\n  return outcome.success;\n}",
                "Server-side verification for Cloudflare Turnstile CAPTCHA."
            )

    # FastAPI (Python) Boilerplates
    if framework == "fastapi":
        if "rate_limit" in feature:
            return BoilerplateResult(
                "FastAPI Limiter (Redis)",
                "from fastapi import FastAPI, Depends\nfrom fastapi_limiter import FastAPILimiter\nfrom fastapi_limiter.depends import RateLimiter\nimport aioredis\n\napp = FastAPI()\n\n@app.on_event('startup')\nasync def startup():\n    redis = await aioredis.from_url('redis://localhost', encoding='utf-8', decode_responses=True)\n    await FastAPILimiter.init(redis)\n\n@app.get('/', dependencies=[Depends(RateLimiter(times=2, seconds=5))])\nasync def index():\n    return {'msg': 'Hello World'}",
                "Rate limiting per route using fastapi-limiter and Redis."
            )
        if "validation" in feature:
            return BoilerplateResult(
                "Pydantic Request Validation",
                "from pydantic import BaseModel, EmailStr, Field\n\nclass UserSignup(BaseModel):\n    email: EmailStr\n    password: str = Field(..., min_length=8)\n    age: int = Field(..., ge=18)\n\n@app.post('/signup')\nasync def signup(user: UserSignup):\n    return {'status': 'ok', 'user': user}",
                "Automatic request validation and documentation using Pydantic models."
            )

    # Express (Node.js) Boilerplates
    if framework == "express":
        if "rate_limit" in feature:
            return BoilerplateResult(
                "Express Rate Limit",
                "const rateLimit = require('express-rate-limit');\n\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100, // Limit each IP to 100 requests per `window`\n  standardHeaders: true,\n  legacyHeaders: false,\n});\n\napp.use('/api/', limiter);",
                "Standard rate limiting middleware for Express apps."
            )
        if "cors" in feature:
            return BoilerplateResult(
                "Secure CORS Configuration",
                "const cors = require('cors');\n\nconst corsOptions = {\n  origin: ['https://yourdomain.com', 'https://admin.yourdomain.com'],\n  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',\n  credentials: true,\n  optionsSuccessStatus: 204\n};\n\napp.use(cors(corsOptions));",
                "CORS middleware with explicit origin whitelist."
            )

    # SQL/Database Boilerplates
    if "sql" in framework or "database" in framework:
        if "rls" in feature:
            return BoilerplateResult(
                "PostgreSQL Row Level Security",
                "-- Enable RLS\nALTER TABLE profiles ENABLE ROW LEVEL SECURITY;\n\n-- Create Policy (Only owner can read)\nCREATE POLICY \"Users can only see their own profile\" \nON profiles FOR SELECT \nUSING (auth.uid() = id);\n\n-- Create Policy (Only owner can update)\nCREATE POLICY \"Users can update their own profile\"\nON profiles FOR UPDATE\nUSING (auth.uid() = id);",
                "Standard PostgreSQL RLS setup for multi-tenant applications."
            )

    return None
