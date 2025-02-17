import faiss
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from mlxtend.frequent_patterns import apriori, association_rules
import pandas as pd

# Load FAISS index
index = faiss.read_index("faiss_index.bin")

# Get all embeddings
embeddings = np.zeros((index.ntotal, 768))
for i in range(index.ntotal):
    embeddings[i] = index.reconstruct(i)  # Reconstruct stored vectors

# Cluster embeddings
n_clusters = 15  # Arbitrary, TODO: find better way of assigning this (elbow method, silhouette score)
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
clusters = kmeans.fit_predict(embeddings)

print(f"Cluster distribution: {np.bincount(clusters)}")

# Pick a sample vulnerable function embedding
query_embedding = embeddings[0].reshape(1, -1)

# Search for similar embeddings in FAISS
D, I = index.search(query_embedding, 5)  # Find top-5 nearest vulnerabilities

print(f"Top matches I: {I}")
print(f"Top matches D: {D}")

print("cluster counts: ", np.bincount(clusters))

