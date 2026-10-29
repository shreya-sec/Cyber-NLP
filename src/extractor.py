import os
import re
import json
import pandas as pd
import spacy
from spacy.pipeline import EntityRuler

class ThreatIntelPipeline:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.df = None
        self.nlp = spacy.blank("en")
        self._setup_nlp_ruler()

    def load_data(self):
        """Load the pre-processed threat intelligence dataset."""
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"Dataset not found at {self.csv_path}")
        self.df = pd.read_csv(r"C:\Users\Shreya\Downloads\Cyber-NLP\Cyber-Threat-Intelligence-Custom-Data_new_processed.csv")
        print(f"[+] Dataset successfully loaded. Total threat reports/records: {len(self.df)}")

    def _setup_nlp_ruler(self):
        """Configure spaCy Entity Ruler with RegEx patterns for IOC extraction."""
        ruler = self.nlp.add_pipe("entity_ruler", config={"overwrite_ents": True})
        patterns = [
            {"label": "IPV4", "pattern": [{"TEXT": {"REGEX": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"}}]},
            {"label": "HASH_MD5_SHA", "pattern": [{"TEXT": {"REGEX": r"^[a-fA-F0-9]{32,64}$"}}]},
            {"label": "CVE_ID", "pattern": [{"TEXT": {"REGEX": r"(?i)^CVE-[0-9]{4}-[0-9]{4,}$"}}]},
            {"label": "URL_DOMAIN", "pattern": [{"TEXT": {"REGEX": r"https?://[^\s]+"}}] }
        ]
        ruler.add_patterns(patterns)

    def analyze_dataset_labels(self):
        """Summarize existing entity labels annotated in the dataset."""
        if self.df is None:
            self.load_data()
        
        label_columns = ['label_1', 'label_2', 'label_3']
        all_labels = []
        for col in label_columns:
            if col in self.df.columns:
                all_labels.extend(self.df[col].dropna().tolist())
        
        label_counts = pd.Series(all_labels).value_counts().reset_index()
        label_counts.columns = ['Entity Label', 'Frequency']
        print("\n--- Dataset Entity Label Distribution ---")
        print(label_counts.to_string(index=False))
        return label_counts

    def extract_iocs_from_corpus(self, sample_size=5):
        """Extract structural IOCs (IPs, Hashes, CVEs) from the text column."""
        print(f"\n--- Extracting IOCs from First {sample_size} Threat Reports ---")
        results = []
        
        for idx, row in self.df.head(sample_size).iterrows():
            text = row.get('text', '')
            doc = self.nlp(text)
            
            extracted_ips = set()
            extracted_hashes = set()
            extracted_cves = set()
            
            for ent in doc.ents:
                if ent.label_ == "IPV4":
                    extracted_ips.add(ent.text)
                elif ent.label_ == "HASH_MD5_SHA":
                    extracted_hashes.add(ent.text)
                elif ent.label_ == "CVE_ID":
                    extracted_cves.add(ent.text.upper())
            
            report_summary = {
                "Record_ID": row.get('id', idx),
                "Snippet": text[:100] + "...",
                "Extracted_IPs": list(extracted_ips),
                "Extracted_Hashes": list(extracted_hashes),
                "Extracted_CVEs": list(extracted_cves)
            }
            results.append(report_summary)
            
        print(json.dumps(results, indent=4))
        return results

if __name__ == "__main__":
    # Path to your dataset inside the data folder
    dataset_file = r"C:\Users\Shreya\Downloads\Cyber-NLP\Cyber-Threat-Intelligence-Custom-Data_new_processed.csv"
    
    pipeline = ThreatIntelPipeline(dataset_file)
    pipeline.load_data()
    pipeline.analyze_dataset_labels()
    pipeline.extract_iocs_from_corpus(sample_size=3)