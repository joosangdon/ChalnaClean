# image_analyzer.py : 이미지 선명도(Laplacian) 분석 및 pHash 유사도 클러스터링 핵심 모듈
import io
import sys
import base64
from pathlib import Path
from typing import Dict, List, Any

import cv2
import numpy as np
import imagehash
from PIL import Image, ImageOps

# [STEP 1 실험을 통해 확정한 임계값 상수]
BLUR_THRESHOLD = 100.0      # Laplacian 분산값이 100.0 미만이면 흔들린(저화질) 사진으로 판정
LOW_RES_WIDTH = 640         # 가로 또는 세로 해상도가 640px 미만이면 저해상도로 판정
PHASH_DISTANCE_LIMIT = 10   # 64비트 pHash 간 해밍 거리가 10 이하이면 유사/중복 그룹으로 분류


def analyze_image_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """
    단일 이미지 바이트를 메모리 상에서 분석하여 해상도, 흐림 점수, pHash, 썸네일을 반환합니다.
    (이후 app.py의 /api/analyze 라우터에서 직접 호출하는 핵심 함수)
    """
    np_arr = np.frombuffer(raw_bytes, np.uint8)
    cv_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if cv_img is None:
        raise ValueError("유효하지 않은 이미지 포맷입니다.")

    # 1. OpenCV Laplacian 분산 기반 흐림도( 선명도 ) 측정
    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    blur_score = float(cv2.Laplacian(gray, cv2.CV_64F).var())

    # 2. Pillow 로드 및 64-bit Perceptual Hash(pHash) 추출
    pil_img = ImageOps.exif_transpose(Image.open(io.BytesIO(raw_bytes)))
    width, height = pil_img.size
    phash_obj = imagehash.phash(pil_img)

    is_blurry = blur_score < BLUR_THRESHOLD
    is_low_res = width < LOW_RES_WIDTH or height < LOW_RES_WIDTH
    is_low_quality = is_blurry or is_low_res

    # 3. 웹 대시보드 렌더링용 인메모리 썸네일 생성
    thumb_img = pil_img.copy()
    thumb_img.thumbnail((300, 300))
    if thumb_img.mode in ("RGBA", "P"):
        thumb_img = thumb_img.convert("RGB")
    thumb_io = io.BytesIO()
    thumb_img.save(thumb_io, format="JPEG", quality=75)
    thumb_b64 = base64.b64encode(thumb_io.getvalue()).decode("utf-8")

    return {
        "width": width,
        "height": height,
        "blur_score": round(blur_score, 2),
        "is_blurry": is_blurry,
        "is_low_res": is_low_res,
        "is_low_quality": is_low_quality,
        "phash_obj": phash_obj,
        "phash_str": str(phash_obj),
        "thumbnail_b64": f"data:image/jpeg;base64,{thumb_b64}",
    }


def cluster_similar_images(analyzed_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    분석된 이미지 리스트의 pHash 해밍 거리를 비교하여 유사·중복 사진 그룹 ID를 부여합니다.
    """
    n = len(analyzed_items)
    visited = [False] * n
    group_counter = 1

    for i in range(n):
        if visited[i]:
            continue
        current_group = [i]
        visited[i] = True

        for j in range(i + 1, n):
            if visited[j]:
                continue
            distance = analyzed_items[i]["phash_obj"] - analyzed_items[j]["phash_obj"]
            if distance <= PHASH_DISTANCE_LIMIT:
                visited[j] = True
                current_group.append(j)

        if len(current_group) > 1:
            for idx in current_group:
                analyzed_items[idx]["group_id"] = group_counter
                analyzed_items[idx]["is_similar"] = True
            group_counter += 1
        else:
            analyzed_items[i]["group_id"] = None
            analyzed_items[i]["is_similar"] = False

    return analyzed_items


# =====================================================================
# 모듈 단독 실행 시: [STEP 1] 알고리즘 임계값 검증 CLI 테스트 수행
# =====================================================================
def _generate_test_samples():
    np.random.seed(42)
    base = np.zeros((600, 800, 3), dtype=np.uint8)
    cv2.rectangle(base, (80, 80), (450, 420), (220, 180, 90), -1)
    cv2.circle(base, (550, 300), 140, (70, 130, 230), -1)
    cv2.putText(base, "ChalnaClean Engine", (110, 520), cv2.FONT_HERSHEY_SIMPLEX, 1.7, (255, 255, 255), 3)
    noise = np.random.randint(0, 35, (600, 800, 3), dtype=np.uint8)
    clear_img = cv2.add(base, noise)

    burst_img = cv2.convertScaleAbs(clear_img, alpha=1.03, beta=5)
    blurred_img = cv2.GaussianBlur(clear_img, (15, 15), 5)

    diff_img = np.zeros((600, 800, 3), dtype=np.uint8)
    for i in range(0, 800, 40):
        cv2.line(diff_img, (i, 0), (800 - i, 600), (100, 240, 120), 4)
    cv2.rectangle(diff_img, (250, 150), (650, 480), (40, 60, 210), -1)

    raw_list = [
        ("sample_01_clear.jpg", clear_img, 95),
        ("sample_02_burst_sim.jpg", burst_img, 70),
        ("sample_03_blurred.jpg", blurred_img, 90),
        ("sample_04_different.jpg", diff_img, 95),
    ]
    output = []
    for name, mat, q in raw_list:
        ok, buf = cv2.imencode(".jpg", mat, [int(cv2.IMWRITE_JPEG_QUALITY), q])
        if ok:
            output.append((name, buf.tobytes()))
    return output


if __name__ == "__main__":
    print("=" * 80)
    print("[image_analyzer.py] Laplacian 흐림 감지 및 pHash 해밍 거리 엔진 단독 검증")
    print("=" * 80)

    cli_paths = sys.argv[1:]
    if cli_paths:
        samples = [(Path(p).name, Path(p).read_bytes()) for p in cli_paths if Path(p).exists()]
    else:
        samples = _generate_test_samples()

    analyzed = []
    for fname, b_data in samples:
        meta = analyze_image_bytes(b_data)
        meta["filename"] = fname
        analyzed.append(meta)

    clustered = cluster_similar_images(analyzed)

    for item in clustered:
        q_label = "저화질(Blur)" if item["is_blurry"] else "정상(Clear) "
        g_label = f"유사 그룹 #{item['group_id']}" if item["is_similar"] else "고유 사진"
        print(
            f" • {item['filename']:<24} | {item['width']}x{item['height']:<7} | "
            f"Laplacian: {item['blur_score']:>8.2f} [{q_label}] | pHash: {item['phash_str']} ({g_label})"
        )
    print("=" * 80)