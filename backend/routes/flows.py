"""
SmartShield Backend — Flow Dataset Routes

Serves the DPI engine's flow_dataset.csv as JSON and provides CSV export.
"""

import csv
import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter(prefix="/api/flows", tags=["Flows"])

# Path to the DPI engine's flow dataset
FLOW_CSV_PATHS = [
    Path(__file__).resolve().parent.parent.parent / "dpi-engine" / "data" / "flow_dataset.csv",
    Path(__file__).resolve().parent.parent.parent / "dpi-engine" / "data" / "flow_dataset2.csv",
    Path(__file__).resolve().parent.parent.parent / "dpi-engine" / "flow_dataset.csv",
]


def _find_csv() -> Path | None:
    for p in FLOW_CSV_PATHS:
        if p.exists():
            return p
    return None


def _read_flows(path: Path) -> list[dict]:
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "domain": row.get("domain", ""),
                "protocol": row.get("protocol", ""),
                "packet_count": int(float(row.get("packet_count", 0))),
                "avg_packet_size": float(row.get("avg_packet_size", 0)),
                "flow_duration": float(row.get("flow_duration", 0)),
                "packets_per_second": float(row.get("packets_per_second", 0)),
                "bytes_per_second": float(row.get("bytes_per_second", 0)),
                "category": row.get("category", "other"),
            })
    return rows


@router.get("")
async def get_flows():
    """Return all flows from the dataset as JSON."""
    csv_path = _find_csv()
    if not csv_path:
        return JSONResponse(content=[], status_code=200)
    try:
        flows = _read_flows(csv_path)
        return JSONResponse(content=flows)
    except Exception as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=500)


@router.get("/export")
async def export_csv():
    """Download the raw CSV file."""
    csv_path = _find_csv()
    if not csv_path:
        return JSONResponse(content={"error": "No dataset found"}, status_code=404)
    return FileResponse(
        path=str(csv_path),
        media_type="text/csv",
        filename="smartshield_flows.csv",
    )
