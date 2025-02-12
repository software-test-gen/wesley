# Code Vulnerability Analysis with FAISS and CodeBERT

## Overview
This repository provides a framework for analyzing and clustering vulnerable code snippets using **FAISS**, **CodeBERT**, and **K-Means clustering**. The pipeline extracts vulnerable code from a dataset, embeds it using a transformer-based model, indexes it with FAISS for similarity search, and then clusters similar vulnerabilities for further analysis.

## Files in This Repository
- **`main.py`** - Downloads the dataset, preprocesses the data, generates embeddings for vulnerable code using **CodeBERT**, and indexes them using **FAISS**.
- **`analysis.py`** - Loads the indexed embeddings, clusters them using **K-Means**, and applies **PCA** for visualization and pattern mining using **Apriori association rules**.

---

## Installation and Setup
### Prerequisites
Ensure you have Python 3.x installed. I recommend using a virtual enivronment to install the packages as shown below:
```bash
python3 -m venv venv
source venv/bin/activate # for Linux
pip install -r requirements.txt
```

### Running the Code
1. Run `main.py` to preprocess the dataset and generate embeddings:
   ```bash
   python main.py
   ```
   This script will:
   - Download the **DiverseVul-Cleaned.csv** dataset from Kaggle
   - Extract vulnerable (bad) and non-vulnerable (good) code snippets
   - Generate embeddings using **Microsoft CodeBERT**
   - Store the embeddings in a **FAISS index**

2. Run `analysis.py` to perform clustering and pattern mining:
   ```bash
   python analysis.py
   ```
   This script will:
   - Load the stored FAISS index
   - Cluster the embeddings using **K-Means**
   - Perform **Association Rule Mining** on vulnerabilities

---

## Step-by-Step Walkthrough

### `main.py` - Preprocessing and FAISS Indexing
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
4. **Save FAISS Index**: The FAISS index is stored as `faiss_index.bin` for later retrieval.

---

### `analysis.py` - Clustering and Visualization
1. **Load FAISS Index**:
   - Reads the stored embeddings from `faiss_index.bin`.
2. **K-Means Clustering**:
   - Clusters embeddings into 5 groups (configurable).
   - Prints the cluster distribution.
3. **Nearest Neighbor Search**:
   - Retrieves the top-5 nearest vulnerable code snippets based on FAISS index.
4. **Dimensionality Reduction (PCA)**:
   - *probably going to remove this*
   - Reduces embedding dimensions from **768D to 2D**.
   - Plots clusters using **Matplotlib**.
5. **Association Rule Mining**:
   *currently uses too much RAM*
   - Converts embeddings into a **binary format**.
   - Applies **Apriori algorithm** to identify frequent patterns in vulnerabilities.
   - Extracts association rules with high confidence.

---

## Outputs
- `good.csv` - Preprocessed dataset containing non-vulnerable code snippets.
- `bad.csv` - Preprocessed dataset containing vulnerable code snippets.
- `faiss_index.bin` - FAISS index containing stored embeddings.
- **Clustering visualization** - A scatter plot of clustered vulnerabilities.
- **Association rules** - Patterns extracted from vulnerability embeddings.

---

## Future Improvements
- Use **HDBSCAN** for better clustering of vulnerabilities.

---


