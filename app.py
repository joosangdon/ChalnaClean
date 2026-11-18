# app.py : [STEP 2 버전] 모듈 분리형 다중 사진 분석 및 초기 암호화(Base64 v1) 웹 서버
import io
import uuid
from pathlib import Path
from typing import Dict, List, Any

from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag

from file_validator import validate_image_upload
from image_analyzer import analyze_image_bytes, cluster_similar_images
from crypto_vault import encrypt_image_b64_v1, decrypt_image_b64_v1

app = Flask(__name__)
STORAGE_DIR = Path("encrypted_storage")
STORAGE_DIR.mkdir(exist_ok=True)

TEMP_MEMORY_CACHE: Dict[str, Dict[str, Any]] = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "photos" not in request.files:
        return jsonify({"error": "업로드된 파일이 없습니다."}), 400

    files = request.files.getlist("photos")
    TEMP_MEMORY_CACHE.clear()
    analyzed_items: List[Dict[str, Any]] = []

    for f in files:
        if not f.filename:
            continue
        raw_bytes = f.read()

        is_valid, _ = validate_image_upload(f.filename, f.content_type, raw_bytes)
        if not is_valid:
            continue

        try:
            meta = analyze_image_bytes(raw_bytes)
        except Exception:
            continue

        temp_id = uuid.uuid4().hex
        safe_name = secure_filename(f.filename) or f"photo_{temp_id[:6]}.jpg"

        TEMP_MEMORY_CACHE[temp_id] = {
            "filename": safe_name,
            "raw_bytes": raw_bytes,
        }
        analyzed_items.append({
            "temp_id": temp_id,
            "filename": safe_name,
            **meta,
        })

    clustered_items = cluster_similar_images(analyzed_items)
    response_list = [
        {k: v for k, v in item.items() if k != "phash_obj"}
        for item in clustered_items
    ]
    return jsonify({"results": response_list})


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(silent=True) or {}
    selected_ids = data.get("temp_ids", [])
    if not selected_ids:
        return jsonify({"error": "암호화할 사진이 선택되지 않았습니다."}), 400

    saved_files = []
    for tid in selected_ids:
        cached = TEMP_MEMORY_CACHE.get(tid)
        if not cached:
            continue

        encrypted_blob = encrypt_image_b64_v1(cached["raw_bytes"])
        stem = Path(cached["filename"]).stem
        enc_filename = f"{stem}_{uuid.uuid4().hex[:8]}.enc"
        (STORAGE_DIR / enc_filename).write_bytes(encrypted_blob)

        saved_files.append(enc_filename)
        del TEMP_MEMORY_CACHE[tid]

    return jsonify({
        "message": f"[STEP 2 v1] {len(saved_files)}개의 사진이 암호화 보관되었습니다.",
        "saved_files": saved_files,
    })


@app.route("/api/vault", methods=["GET"])
def api_vault_list():
    files_info = [
        {"filename": p.name, "size_kb": round(p.stat().st_size / 1024, 2)}
        for p in sorted(STORAGE_DIR.glob("*.enc"), key=lambda x: x.stat().st_mtime, reverse=True)
    ]
    return jsonify({"vault_files": files_info})


@app.route("/api/vault/view/<path:filename>", methods=["GET"])
def api_vault_view(filename: str):
    safe_name = secure_filename(filename)
    target_path = STORAGE_DIR / safe_name
    if not target_path.exists() or target_path.suffix != ".enc":
        abort(404)

    try:
        decrypted_bytes = decrypt_image_b64_v1(target_path.read_bytes())
    except InvalidTag:
        abort(403, description="파일 무결성 검증(GCM Tag) 실패")

    mem_stream = io.BytesIO(decrypted_bytes)
    mem_stream.seek(0)
    mimetype = "image/png" if decrypted_bytes.startswith(b"\x89PNG") else "image/jpeg"
    return send_file(mem_stream, mimetype=mimetype)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)