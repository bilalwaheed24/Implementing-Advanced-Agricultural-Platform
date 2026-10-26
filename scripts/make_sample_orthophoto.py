#!/usr/bin/env python3
"""Write a SYNTHETIC georeferenced orthophoto shaped like OpenDroneMap output.

For testing scripts/odm_ingest.py when no real drone flight has been processed. The image
is labelled synthetic in its metadata: a healthy green crop with one stressed brown patch,
RGBA, DEFLATE-compressed, tiled, in the UTM zone of the given point (as ODM produces).
A real flight processed by OpenDroneMap replaces this file one-for-one.

    python3 scripts/make_sample_orthophoto.py --lat 42.03 --lon -93.63 --out sample_ortho.tif
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np


def main() -> int:
    import rasterio
    from rasterio.transform import from_origin
    from rasterio.warp import transform

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lat", type=float, required=True)
    parser.add_argument("--lon", type=float, required=True)
    parser.add_argument("--size-m", type=float, default=400.0, help="side of the square map")
    parser.add_argument("--gsd", type=float, default=0.25, help="metres per pixel")
    parser.add_argument("--stress", type=float, default=0.25,
                        help="fraction of the field that is stressed (0-0.9)")
    parser.add_argument("--out", type=Path, default=Path("sample_orthophoto.tif"))
    args = parser.parse_args()

    zone = int((args.lon + 180) // 6) + 1
    crs = f"EPSG:{32600 + zone if args.lat >= 0 else 32700 + zone}"
    xs, ys = transform("EPSG:4326", crs, [args.lon], [args.lat])
    size = int(args.size_m / args.gsd)
    rng = np.random.default_rng(42)

    yy, xx = np.mgrid[0:size, 0:size] / size
    red = 70 + 25 * rng.random((size, size))
    green = 130 + 40 * rng.random((size, size)) + 10 * np.sin(xx * 60)   # crop rows
    blue = 50 + 20 * rng.random((size, size))
    radius = np.sqrt(max(0.0, min(0.9, args.stress)) / np.pi)
    patch = (xx - 0.65) ** 2 + (yy - 0.35) ** 2 < radius ** 2
    red[patch] += 70                                                     # brown, dry patch
    green[patch] -= 45
    blue[patch] += 10
    alpha = np.full((size, size), 255)
    alpha[:, : size // 20] = 0                                           # ragged ODM edge
    bands = np.clip(np.stack([red, green, blue, alpha]), 0, 255).astype("uint8")

    profile = {"driver": "GTiff", "width": size, "height": size, "count": 4, "dtype": "uint8",
               "crs": crs, "transform": from_origin(xs[0] - args.size_m / 2,
                                                    ys[0] + args.size_m / 2, args.gsd, args.gsd),
               "compress": "deflate", "tiled": True, "blockxsize": 256, "blockysize": 256,
               "photometric": "RGB"}
    with rasterio.open(args.out, "w", **profile) as dst:
        dst.write(bands)
        dst.colorinterp = [rasterio.enums.ColorInterp.red, rasterio.enums.ColorInterp.green,
                           rasterio.enums.ColorInterp.blue, rasterio.enums.ColorInterp.alpha]
        dst.update_tags(SYNTHETIC="true", NOTE="Synthetic sample for testing odm_ingest.py",
                        GENERATOR="scripts/make_sample_orthophoto.py")
    print(f"wrote {args.out} ({size}x{size} px, {crs}) — SYNTHETIC test image")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
