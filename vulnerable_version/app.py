from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import create_app

app = create_app("vulnerable")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)

