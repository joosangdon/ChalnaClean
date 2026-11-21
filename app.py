# app.py : [STEP 3 최종 버전] EXIF 인메모리 정제 및 바이너리 직접 암호화(v2)가 통합된 Flask 서버
import io
import uuid
from pathlib import Path
from typing import Dict, List, Any

from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag

from file_validator import validate_image_upload
from image_analyzer import analyze_image_bytes, cluster_similar_images
from exif_cleaner import strip_exif_metadata
from crypto_vault import encrypt_image_binary, decrypt_image_binary

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
    """
    [STEP 3 고도화] 선택된 사진을 인메모리에서 1) EXIF 제거 후 2) AES-256-GCM 바이너리 직접 암호화
    """
    data = request.get_json(silent=True) or {}
    selected_ids = data.get("temp_ids", [])
    if not selected_ids:
        return jsonify({"error": "암호화할 사진이 선택되지 않았습니다."}), 400

    # 이전 STEP 2 테스트 때 생성된 레거시(Base64) .enc 파일과 충돌하지 않도록 보관 시 처리
    saved_files = []
    total_removed_tags = 0

    for tid in selected_ids:
        cached = TEMP_MEMORY_CACHE.get(tid)
        if not cached:
            continue

        # 1. [exif_cleaner 모듈] 인메모리 EXIF 메타데이터(위치·기기정보) 완전 제거
        clean_bytes, before_cnt, _ = strip_exif_metadata(cached["raw_bytes"])
        total_removed_tags += before_cnt

        # 2. [crypto_vault v2 모듈] 순수 바이너리 스트림 AES-256-GCM 암호화
        encrypted_blob = encrypt_image_binary(clean_bytes)

        stem = Path(cached["filename"]).stem
        enc_filename = f"{stem}_{uuid.uuid4().hex[:8]}.enc"
        (STORAGE_DIR / enc_filename).write_bytes(encrypted_blob)

        saved_files.append(enc_filename)
        del TEMP_MEMORY_CACHE[tid]

    return jsonify({
        "message": (
            f"{len(saved_files)}개의 사진이 EXIF 정제(제거된 태그 {total_removed_tags}개) 후 "
            f"AES-256-GCM 바이너리로 안전하게 암호화되었습니다."
        ),
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
        decrypted_bytes = decrypt_image_binary(target_path.read_bytes())
    except (InvalidTag, ValueError):
        abort(403, description="파일 무결성 검증(GCM Tag) 실패: 위변조가 탐지되어 열람을 차단합니다.")

    mem_stream = io.BytesIO(decrypted_bytes)
    mem_stream.seek(0)
    mimetype = "image/png" if decrypted_bytes.startswith(b"\x89PNG") else "image/jpeg"
    return send_file(mem_stream, mimetype=mimetype)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)