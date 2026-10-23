from pathlib import Path
p=Path("build/review/bundle-verification.json")
print(p.read_text() if p.exists() else "Build did not complete")
