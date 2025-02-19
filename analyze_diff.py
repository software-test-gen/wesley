import faiss
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

def load_embeddings(faiss_file):
    index = faiss.read_index(faiss_file)
    embeddings = np.zeros((index.ntotal, 768))
    for i in range(index.ntotal):
        embeddings[i] = index.reconstruct(i)
    return embeddings

# Load good and vulnerable code embeddings
good_embeddings = load_embeddings("faiss_good.bin")
vulnerable_embeddings = load_embeddings("faiss_bad.bin")

# Add labels (0 = good, 1 = vulnerable)
good_labels = np.zeros(good_embeddings.shape[0])
vulnerable_labels = np.ones(vulnerable_embeddings.shape[0])

# Merge datasets
all_embeddings = np.vstack((good_embeddings, vulnerable_embeddings))
all_labels = np.concatenate((good_labels, vulnerable_labels))

# Reduce to 2D using PCA
pca = PCA(n_components=2)
embeddings_2d = pca.fit_transform(all_embeddings)

# Scatter plot
plt.figure(figsize=(10, 6))
plt.scatter(embeddings_2d[all_labels == 1, 0], embeddings_2d[all_labels == 1, 1], c="red", label="Vulnerable Code", alpha=0.5)
plt.scatter(embeddings_2d[all_labels == 0, 0], embeddings_2d[all_labels == 0, 1], c="blue", label="Good Code", alpha=0.5)
plt.legend()
plt.title("Embedding Distribution of Good vs. Vulnerable Code")
plt.xlabel("PCA Dimension 1")
plt.ylabel("PCA Dimension 2")
plt.show()

# Cluster embeddings separately
n_clusters = 15  # Adjust based on dataset size

print("Starting kMeans...")
good_kmeans = KMeans(n_clusters=n_clusters, random_state=42).fit(good_embeddings)
print(good_kmeans)
print("Good kMeans complete")
vulnerable_kmeans = KMeans(n_clusters=n_clusters, random_state=42).fit(vulnerable_embeddings)
print("Bad kMeans complete")

# Compute centroid differences
centroid_differences = vulnerable_kmeans.cluster_centers_ - good_kmeans.cluster_centers_

# Show differences
print("Cluster centroid differences (vulnerable - good):")
print(centroid_differences)

# Find the top-k embedding dimensions with the largest differences
top_k = 10
important_features = np.argsort(np.abs(centroid_differences.mean(axis=0)))[-top_k:]

print(f"Top {top_k} embedding dimensions contributing to vulnerability:")
print(important_features)