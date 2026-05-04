# Script to clear all database and JSONL files
# Run with: python clear_all_data.py

import os
import sqlite3
import shutil

# Base directory
base_dir = r"c:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED"

def clear_sqlite_db(db_path):
    """Clear all data from a SQLite database while keeping the schema."""
    if not os.path.exists(db_path):
        print(f"[SKIP] File not found: {db_path}")
        return
    
    # Get the directory and create a temp file
    db_dir = os.path.dirname(db_path)
    temp_db = os.path.join(db_dir, "temp_clear.db")
    
    try:
        # Attach the database and get schema
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        table_names = [t[0] for t in tables]
        
        print(f"[CLEAR] {db_path}")
        print(f"  - Tables found: {table_names}")
        
        # Delete all data from each table
        for table in table_names:
            cursor.execute(f"DELETE FROM {table};")
            print(f"  - Cleared table: {table}")
        
        # Vacuum to reclaim space
        conn.commit()
        cursor.execute("VACUUM;")
        conn.close()
        
        print(f"  - Database cleared successfully!")
        
    except Exception as e:
        print(f"[ERROR] Failed to clear {db_path}: {e}")

def clear_sqlite_wal_files(db_path):
    """Remove WAL and SHM files associated with a database."""
    for ext in ['-shm', '-wal']:
        file_path = db_path + ext
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"[DELETE] {file_path}")
            except Exception as e:
                print(f"[ERROR] Failed to delete {file_path}: {e}")

def clear_jsonl_file(file_path):
    """Clear all content from a JSONL file."""
    if not os.path.exists(file_path):
        print(f"[SKIP] File not found: {file_path}")
        return
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            pass  # Open in write mode and close immediately to truncate
        print(f"[CLEAR] {file_path}")
    except Exception as e:
        print(f"[ERROR] Failed to clear {file_path}: {e}")

# Define all files to clear
sqlite_databases = [
    os.path.join(base_dir, "agent", "runtime", "events.db"),
    os.path.join(base_dir, "worker", "database", "processed_events.db"),
]

wal_shm_files = [
    os.path.join(base_dir, "worker", "database", "processed_events.db-shm"),
    os.path.join(base_dir, "worker", "database", "processed_events.db-wal"),
    os.path.join(base_dir, "agent", "runtime", "agent_store.db-shm"),
    os.path.join(base_dir, "agent", "runtime", "agent_store.db-wal"),
    os.path.join(base_dir, "agent", "runtime", "agent_store.db"),
]

jsonl_files = [
    os.path.join(base_dir, "fragmented_exfil_scenario.jsonl"),
    os.path.join(base_dir, "ML", "synthetic_events.jsonl"),
    os.path.join(base_dir, "Dataset", "train_dataset.jsonl"),
    os.path.join(base_dir, "Dataset", "train_dataset_sample.jsonl"),
    os.path.join(base_dir, "synthetic_events.jsonl"),
    os.path.join(base_dir, "ML", "labeled", "ueba_auto_labeled.jsonl"),
    os.path.join(base_dir, "ML", "labeled", "ueba_labeled.jsonl"),
    os.path.join(base_dir, "ML", "labeled", "ueba_labeling_template.jsonl"),
]

print("=" * 60)
print("CLEARING ALL DATA FILES")
print("=" * 60)

# Clear SQLite databases
print("\n[SQLite Databases]")
for db in sqlite_databases:
    clear_sqlite_db(db)

# Delete WAL/SHM files
print("\n[WAL/SHM Files]")
for f in wal_shm_files:
    if os.path.exists(f):
        try:
            os.remove(f)
            print(f"[DELETE] {f}")
        except Exception as e:
            print(f"[ERROR] Failed to delete {f}: {e}")
    else:
        print(f"[SKIP] File not found: {f}")

# Clear JSONL files
print("\n[JSONL Files]")
for f in jsonl_files:
    clear_jsonl_file(f)

print("\n" + "=" * 60)
print("ALL DATA CLEARED SUCCESSFULLY!")
print("=" * 60)
