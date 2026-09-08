# python/service_daemon.py

# Hexora Service Daemon with verbose logging at every step (aligned with scanner_v2.py)

from __future__ import annotations
import os, sys, time, json, zipfile, shutil, datetime, subprocess, signal
from pathlib import Path
from typing import Optional, Dict, Any
import pymysql

# ----------------------------- CONFIG ------------------------------------

POLL_SEC = 10

DB = dict(
    host="127.0.0.1",
    user="hexora-dev",
    password="mMpkeG4A2apceZ5n",
    database="hexora-dev",
    charset="utf8mb4"
)

BASE_UPLOAD = Path(__file__).resolve().parent.parent / "uploads" / "upload"
BASE_EXTRACT = Path(__file__).resolve().parent.parent / "uploads" / "extract"
BASE_REPORT = Path(__file__).resolve().parent.parent / "uploads" / "report"

# NEW → AI REPORT DIRECTORY
BASE_AIREPORT = Path(__file__).resolve().parent.parent / "uploads" / "AIreports"

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "service.log"

# >>> UPDATED — Use scanner_v2.py instead of scanner.py
SCANNER = Path(__file__).with_name("scanner_v2.py")

RULEPACK_DIR = Path(__file__).resolve().parent / "rulepacks"

# ----------------------------- LOGGING -----------------------------------

def log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"!! Failed to write log file: {e}", file=sys.stderr)
    print(line, file=sys.stderr, flush=True)

# ------------------------------ DB I/O -----------------------------------

def db_conn(autocommit: bool = True):
    return pymysql.connect(**DB, cursorclass=pymysql.cursors.DictCursor, autocommit=autocommit)

def update_status(conn, scan_id: int, *, status=None, progress=None, report_html=None) -> None:
    fields, params = [], []
    if status is not None:
        fields.append("project_status=%s"); params.append(status)
    if progress is not None:
        fields.append("progress=%s"); params.append(int(progress))
    if report_html is not None:
        fields.append("report_html=%s"); params.append(report_html)
    fields.append("updated_at=%s"); params.append(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    params.append(scan_id)
    sql = f"UPDATE scan_projects SET {', '.join(fields)} WHERE id=%s"
    with conn.cursor() as cur:
        cur.execute(sql, params)
    log(f"Updated scan #{scan_id}: {fields}")

def ensure_paths_on_row(row: Dict[str, Any]) -> Dict[str, Any]:
    changed = False
    up, ex, rp = Path(row["upload_path"]), Path(row["extract_path"]), Path(row["report_path"])
    if up != BASE_UPLOAD:
        row["upload_path"] = str(BASE_UPLOAD); changed = True
    if ex != BASE_EXTRACT:
        row["extract_path"] = str(BASE_EXTRACT); changed = True
    if rp != BASE_REPORT:
        row["report_path"] = str(BASE_REPORT); changed = True
    return row if not changed else {**row}

def persist_paths_if_needed(conn, row_before: Dict[str, Any], row_after: Dict[str, Any]) -> None:
    if (row_before["upload_path"] != row_after["upload_path"] or
        row_before["extract_path"] != row_after["extract_path"] or
        row_before["report_path"] != row_after["report_path"]):

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scan_projects SET upload_path=%s, extract_path=%s, report_path=%s WHERE id=%s",
                (row_after["upload_path"], row_after["extract_path"], row_after["report_path"], row_after["id"])
            )
        log(f"Normalized paths for scan #{row_after['id']}")

def claim_next_pending(conn):
    if conn.get_autocommit():
        conn.autocommit(False)
    row = None
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, user_id, project_filename, upload_path, extract_path, report_path, "
                "project_name, project_type, scanned_by "
                "FROM scan_projects "
                "WHERE project_status='pending' "
                "ORDER BY created_at ASC LIMIT 1 FOR UPDATE"
            )
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return None
            original = dict(row)
            row = ensure_paths_on_row(row)
            persist_paths_if_needed(conn, original, row)
            cur.execute(
                "UPDATE scan_projects SET project_status='scanning', progress=%s, updated_at=%s WHERE id=%s",
                (6, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row["id"])
            )
        conn.commit()
        log(f"Claimed scan #{row['id']} for processing")
        return row

    except Exception as e:
        conn.rollback()
        log(f"claim_next_pending error: {e}")
        return None
    finally:
        conn.autocommit(True)

# ----------------------------- ZIP / IO ----------------------------------

def is_zip_file(p: Path) -> bool:
    try: return zipfile.is_zipfile(p)
    except Exception: return False

def _safe_extract_member(zf: zipfile.ZipFile, member: zipfile.ZipInfo, dest: Path) -> None:
    resolved = (dest / Path(*Path(member.filename).parts)).resolve()
    if not str(resolved).startswith(str(dest.resolve())):
        raise RuntimeError(f"Blocked ZipSlip path: {member.filename}")
    if member.is_dir():
        resolved.mkdir(parents=True, exist_ok=True); return
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(member, "r") as src, open(resolved, "wb") as out:
        shutil.copyfileobj(src, out)

def extract_zip(zip_file: Path, dest_dir: Path) -> None:
    if dest_dir.exists(): shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not is_zip_file(zip_file):
        raise RuntimeError("Not a valid ZIP file")
    with zipfile.ZipFile(zip_file, "r") as zf:
        for m in zf.infolist():
            _safe_extract_member(zf, m, dest_dir)
    log(f"Extracted ZIP {zip_file} to {dest_dir}")

# -------------------------- Scanner Runner --------------------------------
# UPDATED FOR scanner_v2.py

def run_scanner(scan_id: int, extracted: Path, report_file: Path, meta: Dict[str, Any]) -> Dict[str, Any]:

    report_file.parent.mkdir(parents=True, exist_ok=True)

    # v2 scanner CLI
    # scanner_v2.py does NOT use:
    #   --id
    #   --meta
    # scanner_v2.py expects:
    #   --src <folder>
    #   --rules <rulepack directory>
    #   --out <json output file>
    json_out = report_file.with_suffix(".json")

    cmd = [
        sys.executable, str(SCANNER),
        "--src", str(extracted),
        "--rules", str(RULEPACK_DIR),
        "--out", str(json_out)
    ]

    log(f"Running scanner_v2: {' '.join(cmd)}")

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if proc.returncode != 0:
        log(f"Scanner_v2 stderr: {proc.stderr.strip()}")
        raise RuntimeError(f"scanner_v2 failed (exit {proc.returncode})")

    # Read JSON output from scanner_v2
    try:
        summary = json.loads(json_out.read_text())
        log(f"Scanner_v2 summary for #{scan_id}: {summary['meta']}")
        return summary
    except Exception as e:
        log(f"Scanner_v2 output parse error: {e}")
        return {"id": scan_id, "counts": {}, "total": 0}

# ----------------------------- Helpers -----------------------------------

def find_uploaded_path(upload_dir: Path, original_name: str) -> Optional[Path]:
    exact = upload_dir / original_name
    if exact.exists():
        log(f"Found exact uploaded file {exact}")
        return exact
    base = os.path.basename(original_name)
    candidates = sorted(upload_dir.glob(f"*{base}*"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    if candidates:
        log(f"Fallback match for {original_name}: {candidates[0]}")
        return candidates[0]
    log(f"No uploaded file found for {original_name}")
    return None

def ensure_base_dirs() -> None:
    for p in (BASE_UPLOAD, BASE_EXTRACT, BASE_REPORT, BASE_AIREPORT, LOG_FILE.parent):
        p.mkdir(parents=True, exist_ok=True)

# ---------------------------- Main Loop -----------------------------------

_STOP = False

def _graceful_signal(sig, frame):
    global _STOP; _STOP = True
    log(f"Received signal {sig}; stopping after current cycle...")

def service_loop() -> None:
    log("Service started")
    ensure_base_dirs()

    while not _STOP:
        try:
            with db_conn(autocommit=True) as conn:
                job = claim_next_pending(conn)

                if not job:
                    log("No pending jobs; sleeping...")
                    time.sleep(POLL_SEC)
                    continue

                scan_id = int(job["id"])
                project_name = job["project_name"]

                log(f"Processing job #{scan_id} ({project_name})")

                upload_dir = Path(job["upload_path"])
                extract_dir = Path(job["extract_path"]) / f"scan_{scan_id}"
                report_dir = Path(job["report_path"])
                report_file = report_dir / f"scan_{scan_id}.html"

                zip_path = find_uploaded_path(upload_dir, job["project_filename"])
                if not zip_path or not zip_path.exists():
                    update_status(conn, scan_id, status="failed", progress=100)
                    log(f"Job #{scan_id} failed: ZIP not found")
                    continue

                try:
                    extract_zip(zip_path, extract_dir)
                except Exception as ex:
                    update_status(conn, scan_id, status="failed", progress=100)
                    log(f"Job #{scan_id} failed during extract: {ex}")
                    continue

                update_status(conn, scan_id, progress=10)
                log(f"Job #{scan_id}: extraction complete, progress=10%")

                meta = {
                    "project_name": project_name,
                    "mode": job["project_type"],
                    "scanned_by": job["scanned_by"],
                    "started_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }

                update_status(conn, scan_id, progress=60)
                log(f"Job #{scan_id}: scanning started, progress=60%")

                try:
                    summary = run_scanner(scan_id, extract_dir, report_file, meta)
                except Exception as ex:
                    update_status(conn, scan_id, status="failed", progress=100)
                    log(f"Job #{scan_id} failed during scanning: {ex}")
                    continue

                findings = summary.get("findings", [])
                dependencies = summary.get("dependencies", [])
                meta2 = summary.get("meta", {})

                # Render enterprise HTML report (scanner_v2 doesn't generate HTML)
                from reports.html_renderer import HTMLRenderer
                final_html = HTMLRenderer.render(findings, meta2)

                # Save HTML
                report_file.write_text(final_html, encoding="utf-8")

                # ============================================================
                # >>> AI SECTION (ONLY FOR AI SCAN MODE)
                # ============================================================
                ai_html = None

                if job["project_type"] == "AI":
                    try:
                        json_file = report_file.with_suffix(".json")
                        ai_json = json_file.read_text(encoding="utf-8")

                        template_path = Path(__file__).resolve().parent.parent / "AIreport.html"
                        template_html = template_path.read_text(encoding="utf-8")

                        import requests

                        AI_API_KEY = "AIzaSyBudGBu2j0i7AIc-tlTYOQDDmmyxVWBOHI"
                        AI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={AI_API_KEY}"

                        payload = {
                            "contents": [{
                                "parts": [{
                                    "text": f"""
You are an enterprise-level security analyst AI.

Using the TEMPLATE below and JSON_INPUT below,
generate a FULL enterprise-grade HTML security report.

Do NOT output markdown.  
Return pure HTML only.  

TEMPLATE:
{template_html}

JSON_INPUT:
{ai_json}

Strict rules:
- Maintain all HTML structure/style from template
- Fill in vulnerabilities list
- Fill severity counts
- Add detailed explanations
- Add remediation steps
- Output ONLY HTML
"""
                                }]
                            }]
                        }

                        log(f"AI request for scan #{scan_id}")
                        resp = requests.post(AI_URL, json=payload)
                        ai_html = resp.json()["candidates"][0]["content"]["parts"][0]["text"]

                        # Clean ```html from Gemini
                        if ai_html.startswith("```"):
                            ai_html = ai_html.strip("`")
                            ai_html = ai_html.replace("html", "", 1).strip()

                        ai_report_path = BASE_AIREPORT / f"scan_{scan_id}.html"
                        ai_report_path.write_text(ai_html, encoding="utf-8")
                        log(f"AI Report saved: {ai_report_path}")

                    except Exception as e:
                        log(f"AI ERROR #{scan_id}: {e}")
                        ai_html = None

                # ============================================================
                # FINAL REPORT STORAGE
                # ============================================================

                update_status(
                    conn,
                    scan_id,
                    status="completed",
                    progress=100,
                    report_html=(ai_html if ai_html else final_html)
                )

                log(f"Job #{scan_id} completed successfully -> {report_file}")

        except Exception as loop_err:
            log(f"Service loop error: {loop_err}")
            time.sleep(5)

    log("Service stopped")

# ------------------------------ Entry -------------------------------------

if __name__ == "__main__":
    signal.signal(getattr(signal, "SIGINT"), _graceful_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _graceful_signal)
    try:
        import pymysql  # noqa
    except Exception:
        print("Please install: pip install pymysql", file=sys.stderr)
        sys.exit(1)
    service_loop()