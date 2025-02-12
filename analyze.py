import faiss
import numpy as np
from sklearn.cluster import KMeans

# Load FAISS index
index = faiss.read_index("faiss_index.bin")

# Get all embeddings
embeddings = np.zeros((index.ntotal, 768))
for i in range(index.ntotal):
    embeddings[i] = index.reconstruct(i)  # Reconstruct stored vectors

# Cluster embeddings
n_clusters = 5  # Choose based on data
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
clusters = kmeans.fit_predict(embeddings)

print(f"Cluster distribution: {np.bincount(clusters)}")
