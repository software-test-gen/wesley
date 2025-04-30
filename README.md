
# Code Vulnerability Analysis with FAISS, CodeBERT, and Mahalanobis Distance

## Overview

This repository provides a framework for analyzing and clustering vulnerable code snippets using advanced machine learning techniques. The pipeline includes:

- **CodeBERT**: Generates embeddings for code snippets to capture semantic information.
- **FAISS**: Performs efficient similarity searches among code embeddings.
- **K-Means Clustering**: Groups similar code snippets based on their embeddings.
- **PCA (Principal Component Analysis)**: Reduces dimensionality for visualization and analysis.
- **Mahalanobis Distance**: Identifies outliers and enhances clustering by considering the covariance structure of the data.

The project draws inspiration and data from a study available on [arXiv](https://arxiv.org/abs/2302.07249), focusing on code vulnerability analysis using machine learning techniques.

## Repository Structure

- `compile_data.py`: Downloads and preprocesses the dataset, generating embeddings for vulnerable code snippets.
- `analyze_diff.py`: Analyzes differences in code snippets to identify vulnerability patterns.
- `cluster_print.py`: Visualizes or outputs clustered code snippets.
- `kmeans_test.py`: Tests the K-Means clustering implementation on the dataset.
- `cluster_analyze.py`: Analyzes clusters formed by K-Means.
- `cluster_deviant.py`: Identifies outliers within clusters using Mahalanobis distance.
- `csv_parse.py`: Parses CSV files containing code snippets and related data.
- `tmux_env.sh`: Sets up a tmux environment for running experiments.
- `requirements.txt`: Lists the Python dependencies required to run the project.
- `pics/`: Contains visualization files like `PCA_code_diff.png`, `good_clustering.png`, and `bad_clustering.png` to provide graphical representations of the clustering results.
- `reports/`: Stores reports and analysis results.

## Mahalanobis Distance-Based Outlier Detection

The `cluster_deviant.py` script enhances the clustering process by identifying outliers using Mahalanobis distance.
This statistical measure accounts for the correlations between variables, providing a more accurate distance metric in multivariate space.

### How It Works

1. **Compute Cluster Statistics**: For each cluster formed by K-Means, calculate the mean vector and covariance matrix of the embeddings.
2. **Calculate Mahalanobis Distance**: For each point in a cluster, compute its Mahalanobis distance from the cluster center.
3. **Identify Outliers**: Points with a Mahalanobis distance exceeding a certain threshold (e.g., based on the chi-squared distribution) are considered outliers.

This approach helps in detecting code snippets that deviate significantly from their cluster, potentially indicating unique or rare vulnerabilities.

## Setup and Usage

### Prerequisites

- Python 3.8 or higher
- Install dependencies using:

```bash
pip install -r requirements.txt
```

### Running the Pipeline

1. **Data Compilation**: Generate embeddings and index them using FAISS.
   ```bash
   python compile_data.py
   ```

2. **Clustering**: Perform K-Means clustering on the embeddings.
   ```bash
   python kmeans_test.py
   ```

3. **Outlier Detection**: Identify outliers within clusters using Mahalanobis distance.
   ```bash
   python cluster_deviant.py
   ```

4. **Visualization**: Visualize the clustering results.
   ```bash
   python cluster_print.py
   ```

## Visualization

The `pics/` directory contains visualizations of the clustering results (from `cluster_print.py`):

- `PCA_code_diff.png`: PCA projection of code differences.
- `good_clustering.png`: Example of well-formed clusters.
- `bad_clustering.png`: Example of poorly formed clusters.

These visualizations aid in assessing the quality of the clustering and the effectiveness of outlier detection.

The `reports/` directory has the reports for each cluster and the deviant functions, all generated from `cluster_analyze.py` and `cluster_deviant.py` respectively.
