import os
import zipfile
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis import analysis
from androguard.core.bytecodes import dvm


def unzip_apk(apk_path, output_dir):
    """Giải nén tệp APK mà không dùng apktool"""
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(output_dir)
    print(f"APK được giải nén vào: {output_dir}")


def analyze_dex(apk_path):
    """Phân tích file APK và trích xuất thông tin node và cạnh từ DEX"""
    apk = APK(apk_path)
    dex_files = apk.get_dex()

    if not dex_files:
        print("Không tìm thấy tệp DEX trong APK")
        return None, None

    d = dvm.DalvikVMFormat(dex_files[0])
    a = analysis.Analysis(d)

    nodes = []
    edges = []

    for method in d.get_methods():
        method_name = method.get_class_name() + '->' + method.get_name()
        nodes.append(method_name)
        xref_from = a.get_method(method).get_xref_from()

        for other_method in xref_from:
            other_method_name = other_method[0].get_class_name(
            ) + '->' + other_method[0].get_name()
            edges.append((other_method_name, method_name))

    return nodes, edges


def plot_graph(nodes, edges, output_img):
    """Vẽ đồ thị từ danh sách node và cạnh và lưu hình ảnh"""
    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    plt.figure(figsize=(12, 8))
    nx.draw(G, with_labels=True, node_size=2000,
            node_color='lightblue', edge_color='gray', font_size=8)
    plt.savefig(output_img, dpi=300)
    plt.show()
    print(f"Đã lưu hình ảnh đồ thị tại: {output_img}")


def save_table(nodes, edges, output_csv):
    """Lưu thông tin node và cạnh vào file CSV"""
    df = pd.DataFrame(edges, columns=['Source', 'Target'])
    df.to_csv(output_csv, index=False)
    print(f"Dữ liệu được lưu tại: {output_csv}")


if __name__ == "__main__":
    apk_file = "sample.apk"  # Thay bằng đường dẫn APK thực tế
    output_folder = "extracted_apk"
    output_csv = "graph_data.csv"
    output_img = "graph_visualization.png"

    unzip_apk(apk_file, output_folder)
    nodes, edges = analyze_dex(apk_file)

    if nodes and edges:
        plot_graph(nodes, edges, output_img)
        save_table(nodes, edges, output_csv)
