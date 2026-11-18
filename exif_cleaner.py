# exif_cleaner.py : [STEP 3] Pillow 기반 민감 EXIF 메타데이터(GPS, 기기정보 등) 인메모리 제거 모듈
import io
from typing import Dict, Any, Tuple
from PIL import Image, ImageOps, ExifTags


def inspect_exif_tags(raw_bytes: bytes) -> Dict[str, Any]:
    """
    이미지 바이트에서 기본 EXIF 태그 및 GPS 하위 IFD 메타데이터 목록을 추출하여 반환합니다.
    """
    with Image.open(io.BytesIO(raw_bytes)) as img:
        exif_data = img.getexif()
        if not exif_data:
            return {}

        readable_tags = {}
        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            readable_tags[tag_name] = str(value)

        # 실제 사진에 GPS 하위 IFD(0x8825)가 존재하는 경우 함께 추출
        try:
            gps_ifd = exif_data.get_ifd(0x8825)
            if gps_ifd:
                readable_tags["GPSInfo_SubIFD"] = f"{len(gps_ifd)} GPS coordinates/tags"
        except Exception:
            pass

        return readable_tags


def strip_exif_metadata(raw_bytes: bytes) -> Tuple[bytes, int, int]:
    """
    원본 이미지 바이트에서 시각적 회전(Orientation)만 픽셀에 반영한 뒤,
    GPS 좌표·촬영 기기·일시 등 모든 EXIF 메타데이터를 제거한 순수 이미지 바이트를 반환합니다.
    반환값: (정제된 이미지 바이트, 제거 전 EXIF 태그 수, 제거 후 EXIF 태그 수)
    """
    before_tags = inspect_exif_tags(raw_bytes)
    before_count = len(before_tags)

    with Image.open(io.BytesIO(raw_bytes)) as img:
        # 1. 스마트폰 사진의 회전 정보(Orientation)를 픽셀 방향에 먼저 적용
        img = ImageOps.exif_transpose(img)

        # 2. 새로운 인메모리 버퍼에 순수 픽셀 데이터만 재인코딩 (EXIF 파라미터 배제)
        clean_io = io.BytesIO()
        save_format = "PNG" if img.mode == "RGBA" else "JPEG"

        if save_format == "JPEG" and img.mode != "RGB":
            img = img.convert("RGB")

        img.save(clean_io, format=save_format, quality=92)
        clean_bytes = clean_io.getvalue()

    after_count = len(inspect_exif_tags(clean_bytes))
    return clean_bytes, before_count, after_count


# =====================================================================
# 모듈 단독 실행 시: [STEP 3] EXIF 메타데이터 제거 전/후 보안 검증 테스트
# =====================================================================
def _create_sample_jpeg_with_exif() -> bytes:
    img = Image.new("RGB", (800, 600), color=(40, 110, 180))
    exif = img.getexif()

    # 인메모리 생성 시 파일 포인터(fp) 오류를 유발하지 않는 표준 TIFF/EXIF 헤더 태그 설정
    exif[0x010F] = "Samsung"                                  # Make (제조사)
    exif[0x0110] = "Galaxy S23+"                              # Model (기기 모델명)
    exif[0x0131] = "One UI 6.1 / ChalnaClean"                 # Software (펌웨어/OS 정보)
    exif[0x0132] = "2026:11:18 12:30:00"                      # DateTime (촬영 일시)
    exif[0x013B] = "User_Private_Owner"                       # Artist (소유자 식별자)
    exif[0x010E] = "GPS_Coord: 37.7519N, 126.7801E (Paju)"    # ImageDescription (위치/메모 메타데이터)

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif.tobytes())
    return buf.getvalue()


if __name__ == "__main__":
    print("=" * 78)
    print("[exif_cleaner.py] 이미지 내 민감 EXIF 메타데이터(위치·기기정보) 인메모리 제거 검증")
    print("=" * 78)

    sample_raw = _create_sample_jpeg_with_exif()
    before_meta = inspect_exif_tags(sample_raw)
    print(f"[1] 제거 전 EXIF 탐지 결과 : 총 {len(before_meta)}개 민감 태그 발견")
    for k, v in before_meta.items():
        print(f"   • {k:<18} : {v}")

    cleaned_raw, cnt_before, cnt_after = strip_exif_metadata(sample_raw)

    print("-" * 78)
    print(f"[2] 제거 후 EXIF 탐지 결과 : 총 {cnt_after}개 태그 ({cnt_before}개 -> {cnt_after}개 완전 소거 완료)")
    print(f"   • 정제 전 크기: {len(sample_raw):,} Bytes  ->  정제 후 크기: {len(cleaned_raw):,} Bytes")
    print("=" * 78)