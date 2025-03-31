import os
import subprocess
from androguard.misc import AnalyzeAPK
import numpy as np
from PIL import Image
import igraph as ig
import pandas as pd

""" Find and process APK files with Apktool """


def handleAPK(APKfile, apktool_path):
    print(f"Decompiling {APKfile} using {apktool_path}...")
    try:
        # apktool d <apk_path> -o <decompile_folder_path> -f
        decompile_folder = APKfile.rsplit(".apk", 1)[0]
        subprocess.run([apktool_path, "d", APKfile, "-o",
                       decompile_folder, "-f"], check=True)
        manifest_path = os.path.join(decompile_folder, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as manifest_file:
                tableBased(manifest_file)
        else:
            print(f"AndroidManifest.xml not found in {decompile_folder}")
    except subprocess.CalledProcessError as e:
        print(f"Error decompile APK {APKfile}: {e}")
    except Exception as e:
        print(f"Error: {e}")


""" Extract Permission """


def tableBased(Manifestfile):
    try:
        # List permission
        permissions = []
        permission_prefix = "android.permission."
        # List intent
        intents = []
        intent_prefix = "android.intent."
        for line in Manifestfile:
            if permission_prefix in line:
                start_id = line.find(permission_prefix) + \
                    len(permission_prefix)
                end_id = line.find('"', start_id)
                permission = line[start_id:end_id].strip()
                if permission and permission not in permissions:
                    permissions.append(permission)
            if intent_prefix in line:
                start_id = line.find(intent_prefix)
                end_id = line.find('"', start_id)
                intent = line[start_id:end_id].strip()
                if intent and intent not in intents:
                    intents.append(intent)
        # Write list
        with open('result.txt', 'w', encoding='utf-8') as wf:
            permissions_str = ", ".join(permissions)
            wf.write(f"permissions = [{permissions_str}]\n")
            intents_str = ", ".join(intents)
            wf.write(f"intents = [{intents_str}]")
        print("The results have been saved to the file result.txt")
    except Exception as e:
        print(f"Error: {e}")


""" Analyze dex file """


def analyzeDex(APKfile):
    a, d, dx = AnalyzeAPK(APKfile)
    return a, d, dx


""" Image-based processing """


def imageBased(APKfile, output_image_path, image_size=(256, 256)):
    try:
        # Analysic APKfile & take bytecode
        a, d, dx = analyzeDex(APKfile)
        bytecode = bytearray()
        for dex in d:
            bytecode.extend(a.get_dex())

        bytecode_array = np.frombuffer(bytecode, dtype=np.uint8)
        total_pixels = image_size[0] * image_size[1]

        # Fix array size
        if len(bytecode_array) > total_pixels:
            bytecode_array = bytecode_array[:total_pixels]
        elif len(bytecode_array) < total_pixels:
            padding = np.zeros(
                total_pixels - len(bytecode_array), dtype=np.uint8)
            bytecode_array = np.concatenate((bytecode_array, padding))

        # Create images from bytecode
        image_data = bytecode_array.reshape(image_size)
        image = Image.fromarray(image_data, mode='L')  # Grayscale image
        image.save(output_image_path, 'PNG')
        print(f"Image have been saved to the file {output_image_path}")
    except Exception as e:
        print(f"Error in imageBased: {e}")


""" Graph-based processing """


def graphBased(APKfile):
    a, d, dx = analyzeDex(APKfile)

    # Create graph
    graph = ig.Graph(directed=True)
    methods = dx.get_methods()
    method_names = [m.get_method().full_name for m in methods]
    graph.add_vertices(method_names)

    edges = []
    for method in methods:
        caller = method.get_method().full_name
        xrefs = method.get_xref_to()
        for xref_class, xref_method, _ in xrefs:
            callee = xref_method.full_name
            if callee in method_names:
                edges.append((caller, callee))
    graph.add_edges(edges)

    # Xuất ra file GML
    graph.write_gml("apk_graph.gml")
    print("Graph have been exported to the file apk_graph.gml")

    # Đọc lại file GML và phân tích
    g = ig.Graph.Read_GML("apk_graph.gml")
    nodes = g.vs["name"]
    edges = [(g.vs[edge.source]["name"], g.vs[edge.target]["name"])
             for edge in g.es]

    print("Danh sách các node:")
    print(nodes)
    print("Danh sách các cạnh:")
    print(edges)
    print(f"Số lượng node: {g.vcount()}")
    print(f"Số lượng cạnh: {g.ecount()}")


def main():
    # Get Apktool path from user
    apktool_path = input(
        "Enter the path of Apktool or press Enter for default (ex: C:/Windows/apktool.bat): ").strip()
    if not apktool_path:
        apktool_path = r"C:\Windows\apktool.bat"
    while not os.path.exists(apktool_path):
        print(f"Apktool not found at: {apktool_path}")
        apktool_path = input(
            "Please enter the correct path to apktool.bat: ").strip()
        if not apktool_path:
            apktool_path = r"C:\Windows\apktool.bat"
    # Get file path from user
    file_path = input(
        "Enter the file path for reconnaissance (ex: C:/Users/YourName/Documents/example.apk): ").strip()
    while not os.path.exists(file_path):
        print(f"File not found at: {file_path}")
        file_path = input("Please enter the correct path: ").strip()
    # Use APK for table-based
    handleAPK(file_path, apktool_path)
    # Image-based
    output_image_path = "output_image.png"
    imageBased(file_path, output_image_path)
    # Graph-based
    graphBased(file_path)


def check_java():
    try:
        subprocess.run(["java", "-version"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print(
            "Error: Java is not installed or not configured properly. Please install JDK.")
        exit(1)


if __name__ == "__main__":
    check_java()
    main()
