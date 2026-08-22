from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.demo_data import generate_labeled_demo_csv

target = ROOT / "ml" / "datasets" / "synthetic-labeled-demo.csv"
target.write_bytes(generate_labeled_demo_csv())
print(f"Wrote SYNTHETIC DEMO DATA to {target}")
