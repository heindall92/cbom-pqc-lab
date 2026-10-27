"""Genera js/samples.js a partir de la carpeta samples/ (datos de ejemplo)."""
import base64, json, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
out = []
for p in sorted((root / "samples").iterdir()):
    if p.name.startswith("README"):
        continue
    data = p.read_bytes()
    if p.suffix == ".der":
        out.append({"name": p.name, "binary": True, "b64": base64.b64encode(data).decode()})
    else:
        out.append({"name": p.name, "binary": False, "text": data.decode("utf-8")})
(root / "js" / "samples.js").write_text(
    "// Generado por tools/build-samples.py. Datos de ejemplo de una entidad ficticia.\nexport const SAMPLES = "
    + json.dumps(out, ensure_ascii=False, indent=1) + ";\n", encoding="utf-8")
print(len(out), "muestras")
