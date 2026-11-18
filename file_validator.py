# file_validator.py : 악성 파일 업로드 방어를 위한 확장자·MIME·Magic Byte 3단계 검증 모듈
from pathlib import Path
from typing import Tuple

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_MIMES = {"image/jpeg", "image/png", "image/webp"}

# 파일 헤더 시그니처(Magic Bytes) 정의
MAGIC_SIGNATURES = {
    "jpeg": b"\xff\xd8\xff",
    "png": b"\x89PNG\r\n\x1a\n",
    "webp_riff": b"RIFF",
    "webp_tail": b"WEBP",
}


def validate_image_upload(filename: str, content_type: str, raw_bytes: bytes) -> Tuple[bool, str]:
    """
    업로드된 파일의 1) 확장자 화이트리스트, 2) MIME-Type, 3) 실제 바이너리 Magic Byte를 검증합니다.
    """
    if not filename or not raw_bytes:
        return False, "빈 파일이거나 파일명이 없습니다."

    # 1단계: 파일 확장자 화이트리스트 검증
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"허용되지 않는 확장자입니다 ({ext})."

    # 2단계: HTTP 헤더 MIME-Type 검증
    if content_type and content_type.lower() not in ALLOWED_MIMES:
        return False, f"허용되지 않는 MIME-Type입니다 ({content_type})."

    # 3단계: 파일 시그니처(Magic Byte) 검증 (확장자 위변조 파일 업로드 방어)
    if len(raw_bytes) < 12:
        return False, "파일 크기가 비정상적으로 작습니다."

    is_jpeg = raw_bytes.startswith(MAGIC_SIGNATURES["jpeg"])
    is_png = raw_bytes.startswith(MAGIC_SIGNATURES["png"])
    is_webp = raw_bytes[:4] == MAGIC_SIGNATURES["webp_riff"] and raw_bytes[8:12] == MAGIC_SIGNATURES["webp_tail"]

    if not (is_jpeg or is_png or is_webp):
        return False, "파일 시그니처(Magic Byte)가 실제 이미지 포맷과 일치하지 않습니다."

    return True, "정상 이미지 검증 통과"


if __name__ == "__main__":
    print("=" * 78)
    print("[file_validator.py] 확장자 위변조 및 Magic Byte 3단계 보안 검증 테스트")
    print("=" * 78)

    # AV 정적 시그니처 오탐을 유발하지 않는 안전한 더미 바이트로 검증 테스트 구성
    test_cases = [
        ("normal_photo.jpg", "image/jpeg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"),
        ("valid_icon.png", "image/png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
        ("malicious_script.exe", "application/octet-stream", b"MZ_FAKE_EXECUTABLE_HEADER_DATA"),
        ("disguised_fake.jpg", "image/jpeg", b"PLAIN_TEXT_DISGUISED_AS_JPEG_FILE"),
    ]

    for fname, mime, payload in test_cases:
        ok, msg = validate_image_upload(fname, mime, payload)
        badge = "PASS (허용)" if ok else "BLOCK (차단)"
        print(f" • {fname:<22} | MIME: {mime:<24} => [{badge}] {msg}")
    print("=" * 78)