import faiss
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

# Load FAISS index
index = faiss.read_index("faiss_good.bin")

# Get all embeddings
embeddings = np.zeros((index.ntotal, 768))
for i in range(index.ntotal):
    embeddings[i] = index.reconstruct(i)  # Reconstruct stored vectors
print("Got embeddings from faiss database, PCA next")

# Perform PCA to reduce to 50 dimensions before t-SNE (improves performance)
pca = PCA(n_components=2)
embeddings_pca = pca.fit_transform(embeddings)
print("Completed PCA dimention reduction, t-SNE for 2D next")

# Cluster embeddings
n_clusters = 15  # Adjust based on data
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
clusters = kmeans.fit_predict(embeddings)
print("Completed kMeans clustering, plotting next")

# Plot the embeddings in 2D
plt.figure(figsize=(10, 6))
scatter = plt.scatter(embeddings_pca[:, 0], embeddings_pca[:, 1], c=clusters, cmap="viridis", alpha=0.7)
plt.colorbar(scatter, label="Cluster ID")
plt.title("PCA Visualization of Embeddings with Clusters")
plt.xlabel("PC1")
plt.ylabel("PC2")
plt.show()
