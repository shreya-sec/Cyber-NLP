import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Ensure data directory exists (or save directly in current folder)
os.makedirs('data', exist_ok=True)

# Load dataset (make sure filename matches your local path)
df = pd.read_csv(r"C:\Users\Shreya\Downloads\Cyber-NLP\Cyber-Threat-Intelligence-Custom-Data_new_processed.csv")

# Extract entity labels
label_columns = ['label_1', 'label_2', 'label_3']
all_labels = []
for col in label_columns:
    if col in df.columns:
        all_labels.extend(df[col].dropna().tolist())

label_counts = pd.Series(all_labels).value_counts().head(10)

# Plot and save correctly
plt.figure(figsize=(10, 5))
sns.barplot(x=label_counts.values, y=label_counts.index, palette='viridis')
plt.title('Top 10 Threat Intelligence Entity Labels in Corpus')
plt.xlabel('Frequency')
plt.ylabel('Entity Type')
plt.tight_layout()

# Save image safely to 'data/entity_distribution.png'
plt.savefig('data/entity_distribution.png')
plt.show()
print("[+] Chart successfully saved to data/entity_distribution.png")