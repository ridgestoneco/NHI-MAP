import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, Date
import csv
import io
import json
from pydantic import BaseModel

from config import get_settings
from database import Base, engine, get_db
from models import Account, Identity, Credential, CrawlRun
from crawlers import aws_crawler, azure_crawler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create tables
Base.metadata.create_all(bind=engine)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="NHI Map", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Depends(api_key_header)):
    settings = get_settings()
    if settings.api_key == "changeme-generate-a-real-key":
        logger.warning("Running with default API key — auth is DISABLED. Set API_KEY in .env for production.")
        return
    if api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


# Mount frontend
app.mount("/static", StaticFiles(directory="../frontend"), name="static")


# --- Pydantic schemas ---

class AccountCreate(BaseModel):
    provider: str
    account_id: str
    subscription_id: Optional[str] = None
    label: str


class AccountOut(BaseModel):
    id: UUID
    provider: str
    account_id: str
    subscription_id: Optional[str]
    label: str
    enabled: bool

    model_config = {"from_attributes": True}


class IdentityOut(BaseModel):
    id: UUID
    provider: str
    identity_type: str
    name: str
    unique_id: str
    sub_type: Optional[str]
    is_active: bool
    cloud_created_at: Optional[datetime]
    last_used_at: Optional[datetime]
    extra_data: Optional[dict]
    discovered_at: Optional[datetime]

    model_config = {"from_attributes": True}


class CredentialOut(BaseModel):
    id: UUID
    credential_type: str
    key_id: Optional[str]
    display_name: Optional[str]
    status: Optional[str]
    created_at: Optional[datetime]
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    extra_data: Optional[dict]

    model_config = {"from_attributes": True}


class CrawlRunOut(BaseModel):
    id: UUID
    account_id: UUID
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    status: str
    identity_count: str
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total_identities: int
    by_provider: dict
    by_type: dict
    accounts: int
    last_crawl: Optional[datetime]


def _latest_crawl_run_ids(db: Session):
    """Get the most recent completed crawl run ID per account."""
    runs = (
        db.query(CrawlRun)
        .filter(CrawlRun.status == "completed")
        .order_by(CrawlRun.finished_at.desc())
        .all()
    )
    seen = set()
    ids = []
    for run in runs:
        if run.account_id not in seen:
            seen.add(run.account_id)
            ids.append(run.id)
    return ids


# --- Detect accounts from CLI ---

@app.post("/api/detect/{provider}", dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def detect_account(request: Request, provider: str, db: Session = Depends(get_db)):
    """Auto-detect account from active CLI session and create it."""
    import subprocess

    if provider not in ("aws", "azure"):
        raise HTTPException(400, "Provider must be 'aws' or 'azure'")

    if provider == "aws":
        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--output", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.error(f"AWS CLI error: {result.stderr.strip()}")
                raise HTTPException(400, "AWS CLI failed — check credentials and try again")
            data = json.loads(result.stdout)
            account_id = data["Account"]
            # Check if already exists
            existing = db.query(Account).filter(Account.provider == "aws", Account.account_id == account_id).first()
            if existing:
                return existing
            account = Account(provider="aws", account_id=account_id, label=f"AWS {account_id}")
            db.add(account)
            db.commit()
            db.refresh(account)
            return account
        except subprocess.TimeoutExpired:
            raise HTTPException(500, "AWS CLI timed out")

    elif provider == "azure":
        try:
            result = subprocess.run(
                ["az", "account", "show", "--output", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.error(f"Azure CLI error: {result.stderr.strip()}")
                raise HTTPException(400, "Azure CLI failed — check credentials and try again")
            data = json.loads(result.stdout)
            tenant_id = data["tenantId"]
            sub_id = data["id"]
            sub_name = data.get("name", "Azure")
            # Check if already exists
            existing = db.query(Account).filter(Account.provider == "azure", Account.account_id == tenant_id).first()
            if existing:
                return existing
            account = Account(
                provider="azure", account_id=tenant_id,
                subscription_id=sub_id, label=sub_name,
            )
            db.add(account)
            db.commit()
            db.refresh(account)
            return account
        except subprocess.TimeoutExpired:
            raise HTTPException(500, "Azure CLI timed out")

    else:
        raise HTTPException(400, f"Unknown provider: {provider}")


# --- Account endpoints ---

@app.post("/api/accounts", response_model=AccountOut, dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def create_account(request: Request, body: AccountCreate, db: Session = Depends(get_db)):
    account = Account(
        provider=body.provider,
        account_id=body.account_id,
        subscription_id=body.subscription_id,
        label=body.label,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


@app.get("/api/accounts", response_model=list[AccountOut], dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def list_accounts(request: Request, db: Session = Depends(get_db)):
    return db.query(Account).all()


@app.delete("/api/accounts/{account_id}", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def delete_account(request: Request, account_id: UUID, db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(404, "Account not found")
    db.delete(account)
    db.commit()
    return {"status": "deleted"}


@app.patch("/api/accounts/{account_id}/toggle", response_model=AccountOut, dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def toggle_account(request: Request, account_id: UUID, db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(404, "Account not found")
    account.enabled = not account.enabled
    db.commit()
    db.refresh(account)
    return account


# --- Crawl endpoints ---

@app.post("/api/crawl/{account_id}", dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def trigger_crawl(request: Request, account_id: UUID, db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(404, "Account not found")
    if not account.enabled:
        raise HTTPException(400, "Account is disabled")

    crawl_run = CrawlRun(account_id=account.id, status="running")
    db.add(crawl_run)
    db.commit()
    db.refresh(crawl_run)

    try:
        if account.provider == "aws":
            total = aws_crawler.run_full_crawl(db, account.id, crawl_run)
        elif account.provider == "azure":
            total = azure_crawler.run_full_crawl(db, account.id, crawl_run)
        else:
            raise HTTPException(400, f"Unknown provider: {account.provider}")

        crawl_run.status = "completed"
        crawl_run.identity_count = str(total)
        crawl_run.finished_at = datetime.utcnow()
        db.commit()
        return {"status": "completed", "identities_found": total, "crawl_run_id": str(crawl_run.id)}

    except Exception as e:
        crawl_run.status = "failed"
        crawl_run.error_message = str(e)
        crawl_run.finished_at = datetime.utcnow()
        db.commit()
        logger.exception(f"Crawl failed for account {account_id}")
        raise HTTPException(500, "Crawl failed — check server logs for details")


@app.post("/api/crawl", dependencies=[Depends(verify_api_key)])
@limiter.limit("2/minute")
async def trigger_crawl_all(request: Request, db: Session = Depends(get_db)):
    """Crawl all enabled accounts."""
    accounts = db.query(Account).filter(Account.enabled == True).all()
    results = []
    for account in accounts:
        crawl_run = CrawlRun(account_id=account.id, status="running")
        db.add(crawl_run)
        db.commit()
        db.refresh(crawl_run)

        try:
            if account.provider == "aws":
                total = aws_crawler.run_full_crawl(db, account.id, crawl_run)
            elif account.provider == "azure":
                total = azure_crawler.run_full_crawl(db, account.id, crawl_run)
            else:
                total = 0

            crawl_run.status = "completed"
            crawl_run.identity_count = str(total)
            crawl_run.finished_at = datetime.utcnow()
            db.commit()
            results.append({"account": account.label, "status": "completed", "identities": total})
        except Exception as e:
            crawl_run.status = "failed"
            crawl_run.error_message = str(e)
            crawl_run.finished_at = datetime.utcnow()
            db.commit()
            results.append({"account": account.label, "status": "failed", "error": str(e)})

    return {"results": results}


@app.get("/api/crawl-runs", response_model=list[CrawlRunOut], dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def list_crawl_runs(request: Request, db: Session = Depends(get_db)):
    return db.query(CrawlRun).order_by(CrawlRun.started_at.desc()).limit(50).all()


# --- Identity endpoints ---

@app.get("/api/identities", response_model=list[IdentityOut], dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def list_identities(
    request: Request,
    db: Session = Depends(get_db),
    provider: Optional[str] = None,
    identity_type: Optional[str] = None,
    account_id: Optional[UUID] = None,
    search: Optional[str] = None,
    active_only: bool = False,
    limit: int = Query(100, le=500),
    offset: int = 0,
):
    """List identities with filtering. Returns the latest crawl run's data."""
    query = db.query(Identity)

    run_ids = _latest_crawl_run_ids(db)
    if run_ids:
        query = query.filter(Identity.crawl_run_id.in_(run_ids))

    if provider:
        query = query.filter(Identity.provider == provider)
    if identity_type:
        query = query.filter(Identity.identity_type == identity_type)
    if search:
        query = query.filter(Identity.name.ilike(f"%{search}%"))
    if active_only:
        query = query.filter(Identity.is_active == True)

    return query.order_by(Identity.name).offset(offset).limit(limit).all()


@app.get("/api/identities/{identity_id}", response_model=IdentityOut, dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def get_identity(request: Request, identity_id: UUID, db: Session = Depends(get_db)):
    identity = db.query(Identity).filter(Identity.id == identity_id).first()
    if not identity:
        raise HTTPException(404, "Identity not found")
    return identity


@app.get("/api/identities/{identity_id}/credentials", response_model=list[CredentialOut], dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def get_identity_credentials(request: Request, identity_id: UUID, db: Session = Depends(get_db)):
    return db.query(Credential).filter(Credential.identity_id == identity_id).all()


# --- Stats ---

@app.get("/api/stats", response_model=StatsOut, dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def get_stats(request: Request, db: Session = Depends(get_db)):
    run_ids = _latest_crawl_run_ids(db)
    base = db.query(Identity)
    if run_ids:
        base = base.filter(Identity.crawl_run_id.in_(run_ids))

    total = base.count()

    by_provider = dict(
        base.with_entities(Identity.provider, func.count(Identity.id))
        .group_by(Identity.provider)
        .all()
    )
    by_type = dict(
        base.with_entities(Identity.identity_type, func.count(Identity.id))
        .group_by(Identity.identity_type)
        .all()
    )
    accounts = db.query(Account).count()
    last_crawl_row = db.query(CrawlRun.finished_at).order_by(CrawlRun.finished_at.desc()).first()
    last_crawl = last_crawl_row[0] if last_crawl_row else None

    return StatsOut(
        total_identities=total,
        by_provider=by_provider,
        by_type=by_type,
        accounts=accounts,
        last_crawl=last_crawl,
    )


# --- Trends ---

@app.get("/api/trends", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def get_trends(request: Request, db: Session = Depends(get_db)):
    """Return 7-day daily identity totals (last crawl per day wins) and new-since-last list."""
    # Get all completed crawl runs in the last 7 days
    cutoff = datetime.utcnow() - timedelta(days=7)
    runs = (
        db.query(CrawlRun)
        .filter(CrawlRun.status == "completed", CrawlRun.finished_at >= cutoff)
        .order_by(CrawlRun.finished_at.desc())
        .all()
    )

    # Build daily rollup: last crawl run per account per day
    # day -> {account_id -> crawl_run_id}
    daily_runs: dict[str, dict] = {}
    for run in runs:
        day = run.finished_at.strftime("%Y-%m-%d")
        if day not in daily_runs:
            daily_runs[day] = {}
        # First seen per account per day = latest (already sorted desc)
        if run.account_id not in daily_runs[day]:
            daily_runs[day][run.account_id] = run.id

    # For each day, count identities by provider from those run IDs
    days_data = []
    for day in sorted(daily_runs.keys()):
        run_ids = list(daily_runs[day].values())
        total = db.query(Identity).filter(Identity.crawl_run_id.in_(run_ids)).count()
        aws = db.query(Identity).filter(Identity.crawl_run_id.in_(run_ids), Identity.provider == "aws").count()
        azure = db.query(Identity).filter(Identity.crawl_run_id.in_(run_ids), Identity.provider == "azure").count()
        days_data.append({"date": day, "total": total, "aws": aws, "azure": azure})

    # New since last: compare latest vs previous crawl run unique_ids
    all_runs = (
        db.query(CrawlRun)
        .filter(CrawlRun.status == "completed")
        .order_by(CrawlRun.finished_at.desc())
        .all()
    )

    # Get latest and previous run IDs per account
    latest_ids = []
    previous_ids = []
    seen = {}  # account_id -> count
    for run in all_runs:
        count = seen.get(run.account_id, 0)
        if count == 0:
            latest_ids.append(run.id)
        elif count == 1:
            previous_ids.append(run.id)
        seen[run.account_id] = count + 1

    new_identities = []
    if latest_ids and previous_ids:
        current_uids = set(
            r[0] for r in db.query(Identity.unique_id)
            .filter(Identity.crawl_run_id.in_(latest_ids)).all()
        )
        previous_uids = set(
            r[0] for r in db.query(Identity.unique_id)
            .filter(Identity.crawl_run_id.in_(previous_ids)).all()
        )
        new_uids = current_uids - previous_uids
        if new_uids:
            new_items = (
                db.query(Identity)
                .filter(Identity.crawl_run_id.in_(latest_ids), Identity.unique_id.in_(new_uids))
                .all()
            )
            new_identities = [
                {"name": i.name, "provider": i.provider, "identity_type": i.identity_type, "unique_id": i.unique_id}
                for i in new_items
            ]

    # Also find removed (with details from previous run)
    removed_identities = []
    if latest_ids and previous_ids:
        removed_uids = previous_uids - current_uids
        if removed_uids:
            removed_items = (
                db.query(Identity)
                .filter(Identity.crawl_run_id.in_(previous_ids), Identity.unique_id.in_(removed_uids))
                .all()
            )
            removed_identities = [
                {"name": i.name, "provider": i.provider, "identity_type": i.identity_type, "unique_id": i.unique_id}
                for i in removed_items
            ]

    return {
        "daily": days_data,
        "new_since_last": new_identities,
        "removed_since_last": removed_identities,
    }


# --- Diff ---

@app.get("/api/diff", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def diff_crawls(
    request: Request,
    date_a: str = Query(..., description="Earlier date YYYY-MM-DD"),
    date_b: str = Query(..., description="Later date YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    """Compare identities between two crawl dates. Returns added, removed, unchanged."""
    def run_ids_for_date(date_str: str):
        """Get the last completed crawl run per account for a given date."""
        runs = (
            db.query(CrawlRun)
            .filter(
                CrawlRun.status == "completed",
                cast(CrawlRun.finished_at, Date) == date_str,
            )
            .order_by(CrawlRun.finished_at.desc())
            .all()
        )
        seen = set()
        ids = []
        for run in runs:
            if run.account_id not in seen:
                seen.add(run.account_id)
                ids.append(run.id)
        return ids

    ids_a = run_ids_for_date(date_a)
    ids_b = run_ids_for_date(date_b)

    if not ids_a and not ids_b:
        return {"added": [], "removed": [], "unchanged_count": 0, "date_a": date_a, "date_b": date_b}

    def identity_map(run_ids):
        """Return {unique_id: identity_dict} for given run IDs."""
        if not run_ids:
            return {}
        items = db.query(Identity).filter(Identity.crawl_run_id.in_(run_ids)).all()
        return {
            i.unique_id: {
                "name": i.name, "provider": i.provider,
                "identity_type": i.identity_type, "sub_type": i.sub_type,
                "unique_id": i.unique_id, "is_active": i.is_active,
            }
            for i in items
        }

    map_a = identity_map(ids_a)
    map_b = identity_map(ids_b)

    uids_a = set(map_a.keys())
    uids_b = set(map_b.keys())

    added = [map_b[uid] for uid in sorted(uids_b - uids_a)]
    removed = [map_a[uid] for uid in sorted(uids_a - uids_b)]
    unchanged_count = len(uids_a & uids_b)

    return {
        "added": added,
        "removed": removed,
        "unchanged_count": unchanged_count,
        "date_a": date_a,
        "date_b": date_b,
    }


@app.get("/api/diff/dates", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def diff_dates(request: Request, db: Session = Depends(get_db)):
    """Return list of dates that have completed crawl runs, most recent first."""
    rows = (
        db.query(cast(CrawlRun.finished_at, Date))
        .filter(CrawlRun.status == "completed", CrawlRun.finished_at.isnot(None))
        .distinct()
        .order_by(cast(CrawlRun.finished_at, Date).desc())
        .all()
    )
    return [str(r[0]) for r in rows]


# --- Risk Scoring ---

def _score_identity(identity: Identity, creds: list[Credential]) -> dict:
    """Compute risk score and findings for a single identity."""
    findings = []
    score = 0
    now = datetime.utcnow()

    # 1. Access key / password credential age > 90 days
    for c in creds:
        if c.credential_type in ("access_key", "password_credential") and c.created_at:
            age_days = (now - c.created_at.replace(tzinfo=None)).days
            if age_days > 90:
                findings.append(f"Credential '{c.display_name or c.key_id or c.credential_type}' is {age_days} days old (no rotation)")
                score += 2

    # 2. Active credentials never used
    for c in creds:
        if c.credential_type in ("access_key", "password_credential"):
            if c.status in (None, "Active") and not c.last_used_at:
                findings.append(f"Credential '{c.display_name or c.key_id or c.credential_type}' has never been used")
                score += 1

    # 3. Multiple active access keys
    active_keys = [c for c in creds if c.credential_type == "access_key" and c.status == "Active"]
    if len(active_keys) > 1:
        findings.append(f"{len(active_keys)} active access keys (should be 1 max)")
        score += 2

    # 4. Expired credentials still attached
    for c in creds:
        if c.expires_at and c.expires_at.replace(tzinfo=None) < now:
            findings.append(f"Credential '{c.display_name or c.key_id or c.credential_type}' expired {(now - c.expires_at.replace(tzinfo=None)).days} days ago")
            score += 1

    # 5. Credentials expiring within 30 days
    for c in creds:
        if c.expires_at:
            days_left = (c.expires_at.replace(tzinfo=None) - now).days
            if 0 < days_left <= 30:
                findings.append(f"Credential '{c.display_name or c.key_id or c.credential_type}' expires in {days_left} days")
                score += 1

    # 6. Uses static access keys instead of managed identity / federation
    if identity.identity_type == "iam_user_service_account" and active_keys:
        findings.append("Uses static access keys (consider IAM role or managed identity)")
        score += 1

    # 7. Identity inactive but has credentials
    if not identity.is_active and len(creds) > 0:
        findings.append("Identity is inactive but still has credentials attached")
        score += 2

    # 8. Azure: Owner or Contributor role assignment
    if identity.extra_data and identity.extra_data.get("role_assignments"):
        high_roles = [ra for ra in identity.extra_data["role_assignments"]
                      if ra.get("role") in ("Owner", "Contributor", "User Access Administrator")]
        if high_roles:
            role_names = ", ".join(set(ra["role"] for ra in high_roles))
            findings.append(f"Has privileged role assignment: {role_names}")
            score += 3

    # 9. AWS: Broad trust policy (wildcard principal)
    if identity.extra_data and identity.extra_data.get("trust_policy"):
        trust_str = json.dumps(identity.extra_data["trust_policy"])
        if '"*"' in trust_str and "Principal" in trust_str:
            findings.append("Trust policy allows wildcard (*) principal")
            score += 3

    # Determine level
    if score >= 5:
        level = "critical"
    elif score >= 3:
        level = "high"
    elif score >= 1:
        level = "medium"
    else:
        level = "low"

    return {
        "identity_id": str(identity.id),
        "name": identity.name,
        "provider": identity.provider,
        "identity_type": identity.identity_type,
        "sub_type": identity.sub_type,
        "unique_id": identity.unique_id,
        "is_active": identity.is_active,
        "score": score,
        "level": level,
        "findings": findings,
        "credential_count": len(creds),
    }


@app.get("/api/risk", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def get_risk_scores(request: Request, db: Session = Depends(get_db)):
    """Score all current identities for risk."""
    run_ids = _latest_crawl_run_ids(db)
    query = db.query(Identity)
    if run_ids:
        query = query.filter(Identity.crawl_run_id.in_(run_ids))
    identities = query.all()

    results = []
    for identity in identities:
        creds = db.query(Credential).filter(Credential.identity_id == identity.id).all()
        scored = _score_identity(identity, creds)
        results.append(scored)

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)

    # Summary counts
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total_findings": 0}
    for r in results:
        summary[r["level"]] += 1
        summary["total_findings"] += len(r["findings"])

    return {"summary": summary, "identities": results}


# --- Export ---

@app.get("/api/export/csv", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def export_csv(request: Request, db: Session = Depends(get_db)):
    """Export all current identities as CSV."""
    run_ids = _latest_crawl_run_ids(db)
    query = db.query(Identity, Account).join(Account, Identity.account_id == Account.id)
    if run_ids:
        query = query.filter(Identity.crawl_run_id.in_(run_ids))
    rows = query.order_by(Identity.name).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Provider", "Type", "Sub-Type", "Status", "Created", "Last Used", "Unique ID", "Account Label", "Account/Tenant ID", "Subscription ID"])
    for i, acct in rows:
        writer.writerow([
            i.name,
            i.provider,
            i.identity_type,
            i.sub_type or "",
            "Active" if i.is_active else "Inactive",
            i.cloud_created_at.isoformat() if i.cloud_created_at else "",
            i.last_used_at.isoformat() if i.last_used_at else "",
            i.unique_id,
            acct.label if acct else "",
            acct.account_id if acct else "",
            acct.subscription_id or "" if acct else "",
        ])

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"nhi_export_{timestamp}.csv"

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# --- Clear all data ---

@app.delete("/api/clear", dependencies=[Depends(verify_api_key)])
@limiter.limit(get_settings().rate_limit)
async def clear_all_data(request: Request, db: Session = Depends(get_db)):
    """Delete all credentials, identities, crawl runs, and accounts."""
    db.query(Credential).delete()
    db.query(Identity).delete()
    db.query(CrawlRun).delete()
    db.query(Account).delete()
    db.commit()
    return {"status": "cleared"}


# --- Serve frontend ---

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("../frontend/index.html", "r") as f:
        return f.read()
