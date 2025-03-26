import pandas as pd
import faiss
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

def extract_values(filepath, cluster, indices):
    """Extract 'func' and 'cwe' values at specific indices and save in Markdown format."""
    df = pd.read_csv(filepath)
    extracted_values = df.loc[df.index.isin(indices), ['func', 'cwe', 'message']]
    
    markdown_output = [f"# Cluster {cluster} Report\n"]
    for i, (_, row) in enumerate(extracted_values.iterrows(), start=1):
        markdown_output.append(f"## Function {i}")
        markdown_output.append(f"```\nFunction: {row['func']}\n```")
        markdown_output.append(f"## Message")
        markdown_output.append(row['message'])
        markdown_output.append(f"## CWE: `{row['cwe']}`\n")
        markdown_output.append("---")
    
    output_file = f"cluster_report{cluster}.md"
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("\n".join(markdown_output))
    print(f"Markdown output saved to {output_file}")

if __name__ == "__main__":
    csv_file = "bad.csv"  # CSV containing function data
    index_file = "faiss_bad.bin"  # FAISS index file
    n_clusters = 6  # Number of clusters (can be adjusted)
    n_funcs = 4  # Number of functions per cluster (can be adjusted)

    # Load FAISS index
    index = faiss.read_index(index_file)
    embeddings = np.zeros((index.ntotal, 768))
    for i in range(index.ntotal):
        embeddings[i] = index.reconstruct(i)
    print("Got embeddings from faiss database")

    # Cluster embeddings
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    clusters = kmeans.fit_predict(embeddings)
    centroids = kmeans.cluster_centers_
    
    cluster_indices = {}
    for cluster_idx, centroid in enumerate(centroids):
        distances = np.linalg.norm(embeddings - centroid, axis=1)
        closest_indices = np.argsort(distances)[:n_funcs]  # Select top N functions per cluster
        cluster_indices[cluster_idx] = closest_indices.tolist()
    
    # Generate reports for each cluster
    for cluster, indices in cluster_indices.items():
        extract_values(csv_file, cluster, indices)
