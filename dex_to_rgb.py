#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import zipfile
import numpy as np
from PIL import Image

# === Cấu hình ===
OUTPUT_DIR = "images_rgb"
IMAGE_WIDTH = 256
os.makedirs(OUTPUT_DIR, exist_ok=True)


def calculate_entropy(data: bytes) -> int:
    if not data:
        return 0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / len(data)
    probs = probs[probs > 0]
    entropy = -np.sum(probs * np.log2(probs))
    return int((entropy / 8.0) * 255)


def generate_rgb_image_from_dex(dex_bytes: bytes, image_width=IMAGE_WIDTH) -> Image.Image:
    def read_u4(bts, off):
        return int.from_bytes(bts[off:off+4], 'little')

    total_size = len(dex_bytes)

    # 1) Xử lý header (first 0x70 bytes)
    sections = []
    HEADER_SIZE = 0x70
    sections.append(dex_bytes[:HEADER_SIZE])

    # 2) Định nghĩa 7 section còn lại với (off_ptr, size_ptr, item_size)
    rest_sections = {
        'string_ids':  (0x38, 0x3C, 4),
        'type_ids':    (0x40, 0x44, 4),
        'proto_ids':   (0x48, 0x4C, 12),
        'field_ids':   (0x50, 0x54, 8),
        'method_ids':  (0x58, 0x5C, 8),
        'class_defs':  (0x60, 0x64, 32),
        'data':        (0x6C, 0x68, None)
    }

    for name, (off_ptr, size_ptr, item_size) in rest_sections.items():
        size = read_u4(dex_bytes, size_ptr)
        offset = read_u4(dex_bytes, off_ptr)
        if name == 'data':
            sec = dex_bytes[offset:]
        else:
            sec = dex_bytes[offset: offset + size * item_size]
        sections.append(sec)

    # 3) Tạo 3 channel R,G,B từ 8 section
    red_ch, green_ch, blue_ch = [], [], []

    for sec in sections:
        sec_len = len(sec)
        if sec_len == 0:
            continue
        ent = calculate_entropy(sec)
        raw = np.frombuffer(sec, dtype=np.uint8).tolist()
        prop = int(sec_len / total_size * 255)

        red_ch   .extend([ent] * sec_len)
        green_ch .extend(raw)
        blue_ch  .extend([prop] * sec_len)

    # 4) Đều hoá độ dài và pad/cut về lưới image_width
    max_len = max(len(red_ch), len(green_ch), len(blue_ch))
    total_pixels = image_width * ((max_len + image_width - 1) // image_width)

    for ch in (red_ch, green_ch, blue_ch):
        if len(ch) < total_pixels:
            ch.extend([0] * (total_pixels - len(ch)))
        else:
            del ch[total_pixels:]

    # 5) Stack vào ảnh RGB
    r = np.array(red_ch,   dtype=np.uint8).reshape(-1, image_width)
    g = np.array(green_ch, dtype=np.uint8).reshape(-1, image_width)
    b = np.array(blue_ch,  dtype=np.uint8).reshape(-1, image_width)
    rgb = np.stack([r, g, b], axis=-1)

    return Image.fromarray(rgb)


def process_apk_for_rgb(apk_path: str):
    print(f"Processing {apk_path} ...")
    try:
        # Trích raw DEX từ APK qua zipfile
        dex_blobs = []
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if name.endswith('.dex'):
                    dex_blobs.append(z.read(name))

        if not dex_blobs:
            print("No DEX found in APK.")
            return

        combined = None
        for raw in dex_blobs:
            img = generate_rgb_image_from_dex(raw)
            if combined is None:
                combined = img
            else:
                combined = Image.fromarray(
                    np.vstack((np.array(combined), np.array(img)))
                )

        out_name = os.path.basename(apk_path).replace('.apk', '.png')
        combined.save(os.path.join(OUTPUT_DIR, out_name))
        print(f"Saved PNG: {out_name}")

    except Exception as e:
        print(f"Error processing {apk_path}: {e}")


def process_apk_folder(folder_path: str):
    if not os.path.isdir(folder_path):
        print("Invalid folder.")
        return
    apks = [f for f in os.listdir(folder_path) if f.endswith('.apk')]
    if not apks:
        print("No APK found.")
        return
    for apk in apks:
        process_apk_for_rgb(os.path.join(folder_path, apk))


if __name__ == '__main__':
    folder = input("Enter APK folder path: ").strip()
    process_apk_folder(folder)
