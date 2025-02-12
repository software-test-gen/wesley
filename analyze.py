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
n_clusters = 5  # Choose based on data
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
clusters = kmeans.fit_predict(embeddings)

print(f"Cluster distribution: {np.bincount(clusters)}")

# Pick a sample vulnerable function embedding
query_embedding = embeddings[0].reshape(1, -1)

# Search for similar embeddings in FAISS
D, I = index.search(query_embedding, 5)  # Find top-5 nearest vulnerabilities

print(f"Top matches: {I}")

# Reduce dimensions for visualization
pca = PCA(n_components=2)
reduced_embeddings = pca.fit_transform(embeddings)

# Plot clusters
plt.scatter(reduced_embeddings[:, 0], reduced_embeddings[:, 1], c=clusters, cmap='viridis')
plt.colorbar()
plt.show()

# Convert embeddings into a binary format for mining
df_encoded = pd.DataFrame((embeddings > 0.5).astype(int))  # Example thresholding
frequent_patterns = apriori(df_encoded, min_support=0.1, use_colnames=True)

# Generate association rules
rules = association_rules(frequent_patterns, metric="confidence", min_threshold=0.7)
print(rules.head())
