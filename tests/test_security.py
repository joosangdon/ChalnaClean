# tests/test_security.py : [STEP 4] AES-256-GCM 무결성·Nonce 고유성·EXIF 소거·Zero-Plaintext 보안 검증
import io
import sys
from pathlib import Path
from PIL import Image
import pytest
from cryptography.exceptions import InvalidTag

# 프로젝트 루트 경로 모듈 Import 지원
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from file_validator import validate_image_upload
from exif_cleaner import strip_exif_metadata, inspect_exif_tags
from crypto_vault import encrypt_image_binary, decrypt_image_binary


def _make_sample_image_bytes() -> bytes:
    img = Image.new("RGB", (400, 300), color=(90, 150, 210))
    exif = img.getexif()
    exif[0x010F] = "Samsung"
    exif[0x0110] = "Galaxy S23+"
    exif[0x010E] = "GPS_37.75N_126.78E"
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif.tobytes())
    return buf.getvalue()


def test_gcm_integrity_tamper_detection():
    """[보안 검증 1] 암호문(.enc) 중 단 1바이트라도 변조 시 InvalidTag 예외로 열람 차단"""
    raw = _make_sample_image_bytes()
    encrypted = bytearray(encrypt_image_binary(raw))

    # 암호문 중간 1바이트를 비트 반전(Tampering) 시뮬레이션
    tamper_idx = len(encrypted) // 2
    encrypted[tamper_idx] ^= 0xFF

    with pytest.raises(InvalidTag):
        decrypt_image_binary(bytes(encrypted))


def test_nonce_uniqueness_across_encryptions():
    """[보안 검증 2] 동일 이미지를 100회 암호화해도 12B Nonce와 암호문이 매번 100% 고유함"""
    raw = _make_sample_image_bytes()
    nonces = set()
    ciphertexts = set()

    for _ in range(100):
        enc = encrypt_image_binary(raw)
        nonces.add(enc[:12])
        ciphertexts.add(enc)

    assert len(nonces) == 100, "Nonce 중복 발생!"
    assert len(ciphertexts) == 100, "동일 평문에 대해 중복 암호문 생성됨!"


def test_exif_zero_remnant_after_pipeline():
    """[보안 검증 3] EXIF 정제 후 암호화·복호화 시 개인정보 메타데이터 0개 유지"""
    raw = _make_sample_image_bytes()
    assert len(inspect_exif_tags(raw)) == 3

    cleaned, before_cnt, after_cnt = strip_exif_metadata(raw)
    assert before_cnt == 3 and after_cnt == 0

    enc = encrypt_image_binary(cleaned)
    dec = decrypt_image_binary(enc)
    assert len(inspect_exif_tags(dec)) == 0


def test_zero_plaintext_footprint_in_ciphertext():
    """[보안 검증 4] 생성된 암호화 바이너리 내에 JPEG/PNG 평문 헤더 시그니처 미존재"""
    raw = _make_sample_image_bytes()
    enc = encrypt_image_binary(raw)

    assert not enc.startswith(b"\xff\xd8\xff"), "평문 JPEG 헤더가 노출됨!"
    assert b"Samsung" not in enc and b"Galaxy" not in enc, "평문 EXIF 문자열이 노출됨!"


def test_magic_byte_spoofing_blocked():
    """[보안 검증 5] 확장자를 .jpg로 위장한 비이미지 악성 페이로드 차단"""
    ok, _ = validate_image_upload("exploit_payload.jpg", "image/jpeg", b"NOT_A_VALID_JPEG_STREAM")
    assert ok is False


if __name__ == "__main__":
    print("=" * 80)
    print("[tests/test_security.py] ChalnaClean 5대 보안·무결성 자동화 검증 리포트")
    print("=" * 80)
    exit_code = pytest.main(["-v", __file__])
    sys.exit(exit_code)