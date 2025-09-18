import pandas as pd
import requests
import io
import gzip
import zipfile
import random

# --- Configuration ---
SAMPLE_SIZE = 50000
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv.gz"
OUTPUT_CSV_PATH = "phishing_dataset_curated.csv"

def build_dataset():
    """
    Downloads, processes, and combines data from Tranco and PhishTank.
    Crucially, it now diversifies the safe URLs to make them more realistic.
    """
    print("🚀 Starting dataset creation process...")
    
    # --- Step 1: Get Legitimate URLs from Tranco ---
    try:
        print(f"Downloading top 1M sites from Tranco...")
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(TRANCO_URL, headers=headers)
        response.raise_for_status()

        zip_file = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_file) as zf:
            csv_filename = zf.namelist()[0] 
            with zf.open(csv_filename) as f:
                df_top_sites = pd.read_csv(f, header=None, names=['rank', 'domain'])
        
        tranco_domains = df_top_sites['domain'].tolist()
        tranco_domains_sampled = random.sample(tranco_domains, SAMPLE_SIZE)
        
        # <<< THE CRUCIAL FIX: Diversify the structure of safe URLs >>>
        print("Diversifying safe URLs to mimic real-world complexity...")
        common_paths = ['/home', '/login', '/search?q=news', '/about-us', '/products', 
                        '/blog/latest-post', '/', '/contact', '/profile/settings', '/index.html']
        
        tranco_urls = []
        for domain in tranco_domains_sampled:
            # Randomly decide to use http or https
            protocol = random.choice(['http://', 'https://'])
            # Randomly decide to include 'www.' or not
            prefix = 'www.' if random.choice([True, False]) else ''
            # Randomly append a common path to add complexity
            path = random.choice(common_paths)
            tranco_urls.append(f"{protocol}{prefix}{domain}{path}")
            
        df_safe = pd.DataFrame(tranco_urls, columns=['URL'])
        df_safe['label'] = 0
        print(f"✅ Successfully processed {len(df_safe)} diverse legitimate URLs.")

    except Exception as e:
        print(f"❌ An error occurred with Tranco data: {e}")
        df_safe = pd.DataFrame()


    # --- Step 2: Get Phishing URLs from PhishTank ---
    try:
        print("\nDownloading verified phishing URLs from PhishTank...")
        response = requests.get(PHISHTANK_URL)
        response.raise_for_status()
        gzip_file = io.BytesIO(response.content)
        with gzip.open(gzip_file, 'rt') as f:
            df_phishing_full = pd.read_csv(f)
        phishing_urls = df_phishing_full['url'].dropna().unique()
        sampled_phishing_urls = random.sample(list(phishing_urls), min(SAMPLE_SIZE, len(phishing_urls)))
        df_phishing = pd.DataFrame(sampled_phishing_urls, columns=['URL'])
        df_phishing['label'] = 1
        print(f"✅ Successfully processed {len(df_phishing)} phishing URLs.")
    except Exception as e:
        print(f"❌ An unexpected error occurred with PhishTank data: {e}")
        df_phishing = pd.DataFrame()

    # --- Step 3: Combine and Save the Dataset ---
    if not df_safe.empty and not df_phishing.empty:
        print("\nCombining and shuffling the datasets...")
        final_df = pd.concat([df_safe, df_phishing], ignore_index=True)
        final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
        final_df.to_csv(OUTPUT_CSV_PATH, index=False)
        print("\n🎉 --- SUCCESS! --- 🎉")
        print(f"Dataset saved to: {OUTPUT_CSV_PATH}")
        print(f"Total URLs: {len(final_df)}")
        print(f"Label distribution:\n{final_df['label'].value_counts()}")
    else:
        print("\n❌ Could not create the dataset as one or both sources failed.")


if __name__ == "__main__":
    build_dataset()