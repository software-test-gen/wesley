import pandas as pd
import faiss
import numpy as np
from scipy.spatial.distance import mahalanobis
from sklearn.cluster import KMeans

def extract_values(filepath, indices, output_file="reports/deviant_report.md"):
    """Extract 'func', 'cwe', and 'message' values at specific indices and save in Markdown format."""
    df = pd.read_csv(filepath)
    extracted_values = df.loc[df.index.isin(indices), ['func', 'cwe', 'message']]

    markdown_output = [f"# Deviant Function Report\n"]
    for i, (_, row) in enumerate(extracted_values.iterrows(), start=1):
        markdown_output.append(f"## Function {i}")
        markdown_output.append(f"```\nFunction: {row['func']}\n```")
        markdown_output.append(f"## Message")
        markdown_output.append(row['message'])
        markdown_output.append(f"## CWE: `{row['cwe']}`\n")
        markdown_output.append("---")

    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("\n".join(markdown_output))

    print(f"Markdown output saved to {output_file}")

if __name__ == "__main__":
    csv_file = "datasets/bad.csv"  # CSV containing function data
    index_file = "datasets/faiss_bad.bin"  # FAISS index file
    n_clusters = 6  # Number of clusters
    n_deviant_funcs = 5  # Number of most deviant functions to extract

    # Load FAISS index
    index = faiss.read_index(index_file)
    embeddings = np.zeros((index.ntotal, 768))
    for i in range(index.ntotal):
        embeddings[i] = index.reconstruct(i)
    print("Got embeddings from faiss database")

    # Cluster embeddings
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    cluster_labels = kmeans.fit_predict(embeddings)
    centroids = kmeans.cluster_centers_

    # Compute covariance matrix and its inverse
    cov_matrix = np.cov(embeddings.T)
    inv_cov_matrix = np.linalg.inv(cov_matrix)

    # Compute Mahalanobis distances for each function
    mahal_distances = np.array([
        mahalanobis(vec, centroids[cluster_labels[i]], inv_cov_matrix) for i, vec in enumerate(embeddings)
    ])

    # Get the most deviant function indices
    deviant_indices = np.argsort(mahal_distances)[-n_deviant_funcs:]  # Top N most deviant

    # Extract and save deviant functions
    extract_values(csv_file, deviant_indices)
