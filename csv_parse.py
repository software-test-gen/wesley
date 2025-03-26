import csv
import pandas as pd

def extract_func_values(filepath, indices, output_file):
    """Extract values under 'func' column at specific indices and save to a file."""
    df = pd.read_csv(filepath)
    func_values = df.loc[df.index.isin(indices), 'func']
    
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write('\n'.join(func_values.astype(str)))

if __name__ == "__main__":
    csv_file = "bad.csv"  # Replace with your CSV file path
    output_file = "output_code.txt"
    indices = [118907  13210 244065  13233 244053 189064  13230 244051  86557 189260]

    
    extract_func_values(csv_file, indices, output_file)
    print(f"Extracted 'func' values saved to {output_file}")