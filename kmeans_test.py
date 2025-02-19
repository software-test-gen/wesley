import faiss
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans

# Function for loading embeddings from faiss bin file to np array
def load_embeddings(faiss_file):
    index = faiss.read_index(faiss_file)
    embeddings = np.zeros((index.ntotal, 768))
    for i in range(index.ntotal):
        embeddings[i] = index.reconstruct(i)
    return embeddings

print("Loading embeddings...")
# Load good and vulnerable code embeddings
good_embeddings = load_embeddings("faiss_good.bin")
vulnerable_embeddings = load_embeddings("faiss_bad.bin")

# Add labels (0 = good, 1 = vulnerable)
good_labels = np.zeros(good_embeddings.shape[0])
vulnerable_labels = np.ones(vulnerable_embeddings.shape[0])

print("All embeddings loaded, combining into one dataset")
# Merge datasets
all_embeddings = np.vstack((good_embeddings, vulnerable_embeddings))
all_labels = np.concatenate((good_labels, vulnerable_labels))

# Select which set of embeddings to test
# test_embeddings = all_embeddings
test_embeddings = good_embeddings
# test_embeddings = vulnerable_embeddings


# Try different numbers of clusters
print("Trying different k values")
inertia_values = []
k_values = range(2, 20)  # Test cluster sizes from 2 to 20

for k in k_values:
    print(f"\tTrying k value: {k}")
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
    kmeans.fit(test_embeddings)
    inertia_values.append(kmeans.inertia_)
    print(f"\t\tineria values: {kmeans.inertia_}")

print("All Ks tested, now plotting")
# Plot inertia vs. k
plt.figure(figsize=(8, 5))
plt.plot(k_values, inertia_values, marker="o")
plt.xlabel("Number of Clusters (k)")
plt.ylabel("Inertia (Sum of Squared Distances)")
plt.title("Elbow Method for Optimal k")
plt.show()
