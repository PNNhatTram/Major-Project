import os
import subprocess
import pandas as pd
import numpy as np
from PIL import Image
from androguard.misc import AnalyzeAPK
import igraph as ig

all_permissions = set()
all_intents = set()
all_apis = set()
apk_results = []

os.makedirs("images", exist_ok=True)
os.makedirs("graphs", exist_ok=True)


def extract_permissions_intents(manifest_lines):
    permissions = set()
    intents = set()
    for line in manifest_lines:
        if "android.permission." in line:
            start = line.find("android.permission.")
            end = line.find('"', start)
            if start != -1 and end != -1:
                permissions.add(line[start:end])
        if "android.intent." in line:
            start = line.find("android.intent.")
            end = line.find('"', start)
            if start != -1 and end != -1:
                intents.add(line[start:end])
    return permissions, intents


def extract_api_calls(dx):
    api_calls = set()
    for method in dx.get_methods():
        for _, call_method, _ in method.get_xref_to():
            if call_method:
                class_name = call_method.class_name
                if class_name.startswith("Landroid/") or class_name.startswith("Ljava/"):
                    api = f"{class_name}->{call_method.name}"
                    api_calls.add(api)
    return api_calls


def get_image_size(apk_path, image_size=(256, 256)):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        bytecode = bytearray()
        for dex in d:
            bytecode.extend(a.get_dex())

        bytecode_array = np.frombuffer(bytecode, dtype=np.uint8)
        total_pixels = image_size[0] * image_size[1]

        if len(bytecode_array) > total_pixels:
            bytecode_array = bytecode_array[:total_pixels]
        elif len(bytecode_array) < total_pixels:
            padding = np.zeros(total_pixels - len(bytecode_array), dtype=np.uint8)
            bytecode_array = np.concatenate((bytecode_array, padding))

        image_data = bytecode_array.reshape(image_size)
        image = Image.fromarray(image_data, mode='L')
        image_name = os.path.basename(apk_path).replace('.apk', '.png')
        image.save(f"images/{image_name}")
        return len(bytecode)
    except Exception as e:
        print(f"[Image] Error: {e}")
        return 0


def get_graph_stats(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        graph = ig.Graph(directed=True)
        methods = dx.get_methods()
        method_names = [m.get_method().full_name for m in methods]
        graph.add_vertices(method_names)

        edges = []
        for method in methods:
            caller = method.get_method().full_name
            for xref_class, xref_method, _ in method.get_xref_to():
                callee = xref_method.full_name
                if callee in method_names:
                    edges.append((caller, callee))
        graph.add_edges(edges)

        graph_name = os.path.basename(apk_path).replace('.apk', '.gml')
        graph.write_gml(f"graphs/{graph_name}")

        return graph.vcount(), graph.ecount()
    except Exception as e:
        print(f"[Graph] Error: {e}")
        return 0, 0


def process_apk(apk_path, apktool_path):
    print(f"\n🔍 Processing {apk_path}")
    decompiled_dir = apk_path.rsplit(".apk", 1)[0]
    try:
        subprocess.run([apktool_path, "d", apk_path, "-o", decompiled_dir, "-f"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            print("❌ AndroidManifest.xml not found!")
            return

        with open(manifest_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            permissions, intents = extract_permissions_intents(lines)
            all_permissions.update(permissions)
            all_intents.update(intents)

        a, d, dx = AnalyzeAPK(apk_path)
        api_calls = extract_api_calls(dx)
        all_apis.update(api_calls)

        image_size = get_image_size(apk_path)
        graph_nodes, graph_edges = get_graph_stats(apk_path)

        apk_results.append({
            "apk": os.path.basename(apk_path),
            "permissions": permissions,
            "intents": intents,
            "apis": api_calls,
            "image_size": image_size,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges
        })

    except subprocess.CalledProcessError as e:
        print(f"❌ Error decompiling {apk_path}: {e}")


def export_to_csv(output_path="result.csv"):
    print("\n📤 Exporting to CSV...")

    all_columns = sorted(list(all_permissions) + list(all_intents) + list(all_apis))
    rows = []

    for entry in apk_results:
        row = {"apk": entry["apk"]}
        for col in all_columns:
            row[col] = 1 if col in entry["permissions"] or col in entry["intents"] or col in entry["apis"] else 0
        # row["image_size"] = entry["image_size"]
        # row["graph_nodes"] = entry["graph_nodes"]
        # row["graph_edges"] = entry["graph_edges"]
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False, encoding='utf-8')
    print(f"✅ CSV saved to {output_path}")


def main():
    apktool_path = input("📍 Path to apktool (default: apktool): ").strip()
    if not apktool_path:
        apktool_path = "apktool"

    folder_path = input("📂 Enter folder path containing APKs: ").strip()
    if not os.path.isdir(folder_path):
        print("❌ Invalid folder path.")
        return

    apk_files = [f for f in os.listdir(folder_path) if f.endswith(".apk")]
    if not apk_files:
        print("❌ No APK files found in folder.")
        return

    for apk in apk_files:
        full_path = os.path.join(folder_path, apk)
        process_apk(full_path, apktool_path)

    export_to_csv()


if __name__ == "__main__":
    main()
