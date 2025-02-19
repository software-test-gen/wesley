# Code Vulnerability Analysis with FAISS and CodeBERT

## Overview
This repository provides a framework for analyzing and clustering vulnerable code snippets using **FAISS**, **CodeBERT**, **K-Means clustering**, **PCA Dimention Reduction**. The pipeline extracts vulnerable code from a dataset, embeds it using a transformer-based model, indexes it with FAISS for similarity search, and then clusters similar vulnerabilities for further analysis.

## Files in This Repository
- **`compile_data.py`** - Downloads the dataset, preprocesses the data, generates embeddings for vulnerable code using **CodeBERT**, and indexes them using **FAISS**.
- **`kmeans_test.py`** - Combines both code FAISS databases and loops through multiple different K values to find the **elbow point** of the clusters' intertia for **K-Means clustering**. 
- **`cluster_print.py`** - Plots the clustering of the embeddings using **PCA** to go from 768 to 2 dimentions.
- **`analysis_diff.py`** - 
---

## Installation and Setup
### Prerequisites
Ensure you have Python 3.x installed. I recommend using a virtual enivronment to install the packages as shown below:
```bash
python3 -m venv venv
source venv/bin/activate # for Linux
pip install -r requirements.txt
```

# Code Vulnerability Analysis with FAISS and CodeBERT

## Overview
This repository provides a framework for analyzing and clustering vulnerable code snippets using **FAISS**, **CodeBERT**, **K-Means clustering**, and **PCA Dimension Reduction**. The pipeline extracts vulnerable code from a dataset, embeds it using a transformer-based model, indexes it with FAISS for similarity search, and then clusters similar vulnerabilities for further analysis.

## Files in This Repository
- **`compile_data.py`** - Downloads the dataset, preprocesses the data, generates embeddings for vulnerable code using **CodeBERT**, and indexes them using **FAISS**.
- **`kmeans_test.py`** - Combines both code FAISS databases and loops through multiple different K values to find the **elbow point** of the clusters' inertia for **K-Means clustering**.
- **`cluster_print.py`** - Plots the clustering of the embeddings using **PCA** to go from 768 to 2 dimensions.
- **`analysis_diff.py`** - Analyzes the differences between vulnerable and non-vulnerable code embeddings by:
  - Loading FAISS indices for good and vulnerable code.
  - Applying **PCA** to visualize the embedding distribution.
  - Clustering embeddings separately using **K-Means**.
  - Computing centroid differences between good and vulnerable clusters.
  - Identifying top embedding dimensions contributing to vulnerabilities.
  - Finding the most vulnerable embeddings based on feature importance.

---

### Running the Code

1. **Preprocess the dataset and generate embeddings**:
   ```bash
   python compile_data.py
   ```
   This script will:
   - Download the **DiverseVul-Cleaned.csv** dataset from Kaggle.
   - Extract vulnerable (bad) and non-vulnerable (good) code snippets.
   - Generate embeddings using **Microsoft CodeBERT**.
   - Store the embeddings in a **FAISS index**.

2. **Perform clustering analysis and visualization**:
   ```bash
   python cluster_print.py
   ```
   This script will:
   - Load the stored FAISS index.
   - Cluster embeddings using **K-Means**.
   - Reduce dimensionality using **PCA**.
   - Plot clusters in a scatter plot.

3. **Analyze the differences between good and vulnerable code**:
   ```bash
   python analysis_diff.py
   ```
   This script will:
   - Load FAISS indices for both good and vulnerable code.
   - Compute PCA-based 2D projections for visualization.
   - Perform **K-Means clustering** on both datasets.
   - Compute differences in cluster centroids.
   - Identify the top embedding dimensions contributing to vulnerabilities.
   - Find the most vulnerable embeddings based on important feature scores.

---

## Step-by-Step Walkthrough

### `compile_data.py` - Preprocessing and FAISS Indexing
1. **Download Dataset**: The script automatically downloads the **DiverseVul-Cleaned.csv** dataset from Kaggle.
2. **Preprocess Data**:
   - Removes unnecessary columns.
   - Splits the dataset into **vulnerable code snippets** and **non-vulnerable code snippets**.
   - Saves them separately into `good.csv` and `bad.csv`.
3. **Generate Embeddings**:
   - Loads the **Microsoft CodeBERT** model.
   - Tokenizes and encodes each vulnerable function (`func` column).
   - Extracts the `[CLS]` embedding as a feature vector.
   - Stores embeddings in a **FAISS index** (768-dimensional L2 distance search).
4. **Save FAISS Index**: The FAISS index is stored as `faiss_good.bin` and `faiss_bad.bin` for later retrieval.

---

### `analysis_diff.py` - Vulnerability Feature Extraction
1. **Load FAISS Index**:
   - Reads the stored embeddings from `faiss_good.bin` and `faiss_bad.bin`.
2. **PCA Visualization**:
   - Reduces embedding dimensions from **768D to 2D**.
   - Generates a scatter plot showing the distribution of good and vulnerable embeddings.
3. **K-Means Clustering**:
   - Separately clusters good and vulnerable embeddings into **15 clusters**.
   - Computes centroid differences between the two clusters.
4. **Feature Importance Analysis**:
   - Identifies the top **10 embedding dimensions** contributing to vulnerabilities.
   - Computes **vulnerability scores** based on these key dimensions.
5. **Identify Most Vulnerable Code Snippets**:
   - Selects the top **20 embeddings** with the highest vulnerability scores.
   - Outputs their indices for further analysis.

---

## Outputs
- `good.csv` - Preprocessed dataset containing non-vulnerable code snippets.
- `bad.csv` - Preprocessed dataset containing vulnerable code snippets.
- `faiss_good.bin` & `faiss_bad.bin` - FAISS indices containing stored embeddings.
- **Clustering visualization** - A scatter plot of clustered vulnerabilities.
- **Centroid Differences** - Feature importance scores for vulnerability detection.
- **Top Vulnerable Embeddings** - Indices of the most vulnerable embeddings.

---

## Conclusion
- Top 10 embedding dimensions contributing to vulnerability: 286, 155, 466, 259, 447, 507, 333, 749,  92, 588
- Top 20 most characteristically vulnerable embedding indices: 101976, 190224, 119550, 158113, 118359, 258303, 230622, 137521,  13210, 244065, 132691, 244053,  13233,  49748, 184823, 13214, 244075, 86557, 13230, 244051


## Future Improvements
- Experiment with **t-SNE** or **UMAP** for dimensionality reduction.

---

