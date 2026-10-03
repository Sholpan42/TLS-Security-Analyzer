from pathlib import Path


def load_core():
    source_path = Path(__file__).parents[1] / "TLS_Analyzer.py"
    source = source_path.read_text(encoding="utf-8-sig")
    core = source.split("# =========================\n# UI\n# =========================")[0]
    namespace = {"__file__": str(source_path), "__name__": "tls_analyzer_core"}
    exec(core, namespace)
    return namespace
