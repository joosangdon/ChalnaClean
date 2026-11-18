# crypto_vault.py : [STEP 2 초기 버전] Base64 인코딩 기반 AES-256-GCM 암호화 모듈 (리팩토링 전)
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


def encrypt_image_b64_v1(raw_bytes: bytes) -> bytes:
    """
    [STEP 2 초기 프로토타입 방식]
    이미지 원본 바이트를 Base64 텍스트로 변환한 뒤 AES-256-GCM 암호화를 수행합니다.
    (문제점: 3바이트 -> 4바이트 ASCII 변환으로 인해 암호문 용량이 약 33% 증가하고 인코딩 지연 발생)
    """
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)

    # 1. 원본 바이너리를 Base64로 인코딩 (1차 용량 팽창 + CPU 오버헤드)
    b64_payload = base64.b64encode(raw_bytes)

    # 2. AES-256-GCM 암호화 수행
    ciphertext_with_tag = aesgcm.encrypt(nonce, b64_payload, associated_data=None)

    # 3. 파일 저장을 위해 다시 Base64 텍스트로 직렬화 (초기 AI 초안의 비효율적 구조)
    combined = nonce + ciphertext_with_tag
    return base64.b64encode(combined)


def decrypt_image_b64_v1(encoded_blob: bytes) -> bytes:
    """
    Base64로 직렬화된 암호문을 역직렬화 및 복호화하여 원본 이미지 바이트를 반환합니다.
    """
    raw_blob = base64.b64decode(encoded_blob)
    nonce = raw_blob[:12]
    ciphertext_with_tag = raw_blob[12:]

    aesgcm = AESGCM(MASTER_KEY)
    decrypted_b64 = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    return base64.b64decode(decrypted_b64)


if __name__ == "__main__":
    print("=" * 78)
    print("[crypto_vault.py v1] 초기 Base64 변환 후 암호화 방식 용량 및 처리 지연 점검")
    print("=" * 78)

    # 고해상도 원본 사진 1장(5MB) 및 10장(50MB) 처리 시뮬레이션
    sample_photo = os.urandom(5 * 1024 * 1024)  # 5.00 MB 가상 이미지
    orig_size_mb = len(sample_photo) / (1024 * 1024)

    t0 = time.perf_counter()
    encrypted_out = encrypt_image_b64_v1(sample_photo)
    elapsed_single = (time.perf_counter() - t0) * 1000
    enc_size_mb = len(encrypted_out) / (1024 * 1024)
    inflation_pct = ((len(encrypted_out) - len(sample_photo)) / len(sample_photo)) * 100

    print(f" • 단일 원본 사진 크기   : {orig_size_mb:.2f} MB")
    print(f" • Base64 암호화 후 크기 : {enc_size_mb:.2f} MB (용량 +{inflation_pct:.1f}% 폭증)")
    print(f" • 단일 사진 암호화 시간 : {elapsed_single:.2f} ms")
    print("-" * 78)
    print(" => [병목 진단] 다중 사진(10장 이상) 업로드 시 Base64 이중 변환으로 인해")
    print("    저장 용량이 크게 늘어나고 메모리 복사 및 I/O 지연이 발생함 -> STEP 3에서 바이너리 직접 암호화로 개선 필요")
    print("=" * 78)