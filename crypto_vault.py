# crypto_vault.py : [STEP 3 리팩토링 완료] 순수 바이너리 스트림 기반 AES-256-GCM 암복호화 모듈 (v2)
import os
import time
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()
RAW_KEY_B64 = os.getenv("AES_MASTER_KEY")
if not RAW_KEY_B64:
    raise RuntimeError(".env 파일에 AES_MASTER_KEY가 설정되지 않았습니다.")

MASTER_KEY = base64.urlsafe_b64decode(RAW_KEY_B64)
NONCE_SIZE = 12  # NIST SP 800-38D 권장 96-bit(12바이트) 고유 Nonce


# =====================================================================
# [STEP 3 최종 방식 (v2)] Base64 오버헤드를 제거한 순수 바이너리 직접 암복호화
# 포맷 구조: [12B Nonce] + [Ciphertext] + [16B GMAC Auth Tag] (총 +28 Bytes만 증가)
# =====================================================================
def encrypt_image_binary(raw_bytes: bytes) -> bytes:
    """
    인메모리 원본(또는 EXIF 정제된) 바이트를 Base64 변환 없이 즉시 AES-256-GCM 바이너리로 암호화합니다.
    """
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_with_tag = aesgcm.encrypt(nonce, raw_bytes, associated_data=None)
    return nonce + ciphertext_with_tag


def decrypt_image_binary(encrypted_blob: bytes) -> bytes:
    """
    바이너리 암호문에서 앞 12바이트 Nonce를 분리하고 무결성(GMAC Tag) 검증 후 복호화합니다.
    1바이트라도 위변조된 경우 InvalidTag 예외가 발생합니다.
    """
    if len(encrypted_blob) < NONCE_SIZE + 16:
        raise ValueError("손상되었거나 유효하지 않은 암호화 데이터입니다.")

    nonce = encrypted_blob[:NONCE_SIZE]
    ciphertext_with_tag = encrypted_blob[NONCE_SIZE:]
    aesgcm = AESGCM(MASTER_KEY)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)


# =====================================================================
# [STEP 2 레거시 방식 (v1)] 리팩토링 전/후 벤치마크 비교를 위해 보존
# =====================================================================
def encrypt_image_b64_v1(raw_bytes: bytes) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(NONCE_SIZE)
    b64_payload = base64.b64encode(raw_bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, b64_payload, associated_data=None)
    return base64.b64encode(nonce + ciphertext_with_tag)


if __name__ == "__main__":
    print("=" * 80)
    print("[crypto_vault.py v2] Base64 암호화(v1) vs 순수 바이너리 암호화(v2) 리팩토링 비교")
    print("=" * 80)

    sample_photo = os.urandom(5 * 1024 * 1024)  # 5.00 MB 고해상도 사진 시뮬레이션
    orig_mb = len(sample_photo) / (1024 * 1024)

    # 1. 기존 v1 (Base64 방식) 측정
    t0 = time.perf_counter()
    out_v1 = encrypt_image_b64_v1(sample_photo)
    ms_v1 = (time.perf_counter() - t0) * 1000
    mb_v1 = len(out_v1) / (1024 * 1024)
    inc_v1 = ((len(out_v1) - len(sample_photo)) / len(sample_photo)) * 100

    # 2. 개선된 v2 (바이너리 직접 암호화 방식) 측정
    t1 = time.perf_counter()
    out_v2 = encrypt_image_binary(sample_photo)
    ms_v2 = (time.perf_counter() - t1) * 1000
    mb_v2 = len(out_v2) / (1024 * 1024)
    overhead_bytes = len(out_v2) - len(sample_photo)

    # 3. 복호화 일치 검증
    recovered = decrypt_image_binary(out_v2)
    assert recovered == sample_photo, "복호화 데이터 불일치!"

    speedup_pct = ((ms_v1 - ms_v2) / ms_v1) * 100
    size_saved_pct = ((len(out_v1) - len(out_v2)) / len(out_v1)) * 100

    print(f" • 원본 이미지 크기          : {orig_mb:.2f} MB ({len(sample_photo):,} Bytes)")
    print("-" * 80)
    print(f" [Before] v1 Base64 암호화   : {mb_v1:.2f} MB (+{inc_v1:.1f}% 폭증) | 소요 시간: {ms_v1:>6.2f} ms")
    print(f" [After]  v2 바이너리 암호화 : {mb_v2:.2f} MB (+{overhead_bytes} Bytes)    | 소요 시간: {ms_v2:>6.2f} ms")
    print("-" * 80)
    print(f" => [리팩토링 성과] 암호문 저장 용량 {size_saved_pct:.1f}% 절감 (불필요한 팽창 0%), "
          f"암호화 처리 속도 {speedup_pct:.1f}% 단축 완료")
    print("=" * 80)