#!/usr/bin/env python3
"""Ingest an OpenDroneMap orthophoto into the platform's secure imagery pipeline.

OpenDroneMap (ODM / WebODM) turns overlapping drone photos into one georeferenced map,
`odm_orthophoto/odm_orthophoto.tif`. This script runs where that file is (the farm's
gateway or the operator's laptop) and:

  1. hashes the actual image file (SHA-256), so the imagery can later be proven unaltered,
  2. computes a vegetation index from the pixels:
       NDVI = (NIR - Red) / (NIR + Red)          when the camera has a near-infrared band
       VARI = (Green - Red) / (Green + Red - Blue) for an ordinary RGB drone camera,
  3. reads the map's footprint and converts it to WGS84 longitude/latitude for QGIS,
  4. sends the statistics, footprint and file hash to the API as a DRONE scene. The API
     verifies the checksum and anchors the file hash on the ledger.

    python3 scripts/odm_ingest.py --orthophoto datasets/aukerman/odm_orthophoto/odm_orthophoto.tif \\
        --field-id <field uuid> --api-url http://127.0.0.1:8000
    python3 scripts/odm_ingest.py --project datasets/aukerman --field-id ... --dry-run

Needs: pip install -r requirements/geo.txt (rasterio). Only this script uses it.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

MAX_SIDE = 2000          # pixels: statistics are computed on a downsampled copy


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyse(path: Path, nir_band: int | None) -> dict:
    import rasterio
    from rasterio.enums import Resampling
    from rasterio.warp import transform_bounds

    with rasterio.open(path) as src:
        if src.crs is None:
            raise SystemExit(f"{path} has no coordinate system; is it an ODM orthophoto?")
        scale = max(src.width, src.height) / MAX_SIDE
        shape = (max(1, int(src.height / max(scale, 1))), max(1, int(src.width / max(scale, 1))))
        data = src.read(out_shape=(src.count, *shape), resampling=Resampling.average)
        data = data.astype("float64")

        # Valid pixels: the alpha band ODM writes as band 4 of an RGBA orthophoto, else nodata.
        valid = np.ones(shape, dtype=bool)
        alpha = [i for i, ci in enumerate(src.colorinterp) if ci.name == "alpha"]
        if alpha:
            valid &= data[alpha[0]] > 0
        elif src.nodata is not None:
            valid &= ~np.all(data == src.nodata, axis=0)

        red, green, blue = data[0], data[1], data[2]
        if nir_band:
            nir = data[nir_band - 1]
            denominator = nir + red
            index_name = "NDVI"
            index = np.where(denominator != 0, (nir - red) / np.where(denominator == 0, 1, denominator), 0)
        else:
            denominator = green + red - blue
            index_name = "VARI"
            index = np.where(np.abs(denominator) > 1e-6,
                             (green - red) / np.where(np.abs(denominator) > 1e-6, denominator, 1), 0)
        values = np.clip(index[valid], -1, 1)
        if values.size == 0:
            raise SystemExit("no valid pixels in the orthophoto")

        west, south, east, north = transform_bounds(src.crs, "EPSG:4326", *src.bounds)
        footprint = {"type": "Polygon", "coordinates": [[
            [round(west, 7), round(south, 7)], [round(east, 7), round(south, 7)],
            [round(east, 7), round(north, 7)], [round(west, 7), round(north, 7)],
            [round(west, 7), round(south, 7)]]]}
        return {
            "index_name": index_name,
            "mean": round(float(values.mean()), 4),
            "low": round(float(np.percentile(values, 5)), 4),     # robust min / max: the 5th
            "high": round(float(np.percentile(values, 95)), 4),   # and 95th percentiles
            "pixels": int(values.size), "size": [src.width, src.height], "bands": src.count,
            "crs": str(src.crs), "footprint": footprint,
        }


def call(api: str, method: str, path: str, body: dict | None = None,
         token: str | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        api.rstrip("/") + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"null")
        except ValueError:
            return error.code, {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--orthophoto", type=Path, help="path to odm_orthophoto.tif")
    source.add_argument("--project", type=Path, help="ODM project folder (uses its orthophoto)")
    parser.add_argument("--field-id", required=True, help="the field this flight covered")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--email", default="farmer@absp.demo",
                        help="a farm operator account (needs telemetry:write)")
    parser.add_argument("--password", default=None, help="prompted for when omitted")
    parser.add_argument("--scene-id", default=None)
    parser.add_argument("--captured-at", default=None, help="ISO time of the flight")
    parser.add_argument("--nir-band", type=int, default=None,
                        help="1-based band number of near-infrared (multispectral cameras only)")
    parser.add_argument("--dry-run", action="store_true", help="analyse only, send nothing")
    args = parser.parse_args()

    path = args.orthophoto or args.project / "odm_orthophoto" / "odm_orthophoto.tif"
    if not path.is_file():
        raise SystemExit(f"orthophoto not found: {path}")

    print(f"Orthophoto      {path}")
    digest = file_sha256(path)
    print(f"File SHA-256    {digest}")
    stats = analyse(path, args.nir_band)
    print(f"Raster          {stats['size'][0]}x{stats['size'][1]} px, {stats['bands']} bands, "
          f"{stats['crs']}")
    print(f"{stats['index_name']:<15} mean {stats['mean']:.3f}  (p5 {stats['low']:.3f}, "
          f"p95 {stats['high']:.3f}) over {stats['pixels']} sampled pixels")
    west, south = stats["footprint"]["coordinates"][0][0]
    east, north = stats["footprint"]["coordinates"][0][2]
    print(f"Footprint WGS84 lon {west:.5f}..{east:.5f}, lat {south:.5f}..{north:.5f}")

    captured = (datetime.fromisoformat(args.captured_at) if args.captured_at
                else datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc))
    if captured.tzinfo is None:
        captured = captured.replace(tzinfo=timezone.utc)
    scene_id = args.scene_id or f"ODM-{captured:%Y%m%d}-{digest[:8].upper()}"

    from app.services.telemetry import scene_checksum                    # noqa: PLC0415

    body = {"scene_id": scene_id, "field_id": args.field_id, "provider": "OpenDroneMap",
            "captured_at": captured.isoformat(), "ndvi_mean": stats["mean"],
            "ndvi_min": min(stats["low"], stats["mean"]), "ndvi_max": max(stats["high"], stats["mean"]),
            "cloud_cover_pct": 0.0, "source": "DRONE", "index_name": stats["index_name"],
            "file_sha256": digest, "footprint_geojson": stats["footprint"]}
    body["checksum"] = scene_checksum(scene_id, args.field_id, captured, stats["mean"], digest)

    if args.dry_run:
        print(json.dumps(body, indent=2))
        return 0

    password = args.password or getpass.getpass(f"Password for {args.email}: ")
    status, login = call(args.api_url, "POST", "/api/v1/auth/login",
                         {"email": args.email, "password": password})
    if status != 200:
        raise SystemExit(f"login failed: {status} {login}")
    status, scene = call(args.api_url, "POST", "/api/v1/telemetry/satellite/scenes", body,
                         login["access_token"])
    if status != 201:
        raise SystemExit(f"ingest refused: {status} {scene}")
    print(f"\nIngested scene  {scene['scene_id']} (source {scene['source']}, "
          f"index {scene['index_name']})")
    print(f"Ledger anchor   {scene.get('anchor_tx_id') or 'not anchored'}")
    print("Open the Satellite & NDVI page, or download the GeoJSON there for QGIS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
