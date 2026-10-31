"""Seed script for populating ChromaDB persistent vector database with CWE rules and security policies."""

import os
import sys
from pathlib import Path

# Add backend directory to sys.path so app modules import cleanly
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.config import CHROMA_DB_PATH
from app.rag_engine import SEED_SECURITY_POLICIES, get_vector_collection


def main():
    print("=" * 60)
    print(" CodeLeak Patrol - ChromaDB Vector Store Seeder")
    print("=" * 60)
    print(f"Target vector store path: {CHROMA_DB_PATH}")

    collection = get_vector_collection(CHROMA_DB_PATH)

    print(f"Seeding {len(SEED_SECURITY_POLICIES)} CWE standards and internal security policies...")

    for policy in SEED_SECURITY_POLICIES:
        print(f"  [+] Seeding: {policy['id']} - {policy['title']}")

    if hasattr(collection, "seed_defaults"):
        collection.seed_defaults()
    else:
        # ChromaDB standard collection
        ids = [p["id"] for p in SEED_SECURITY_POLICIES]
        docs = [p["document"] for p in SEED_SECURITY_POLICIES]
        import json

        metas = [
            {
                "title": p["title"],
                "cwe_id": p["cwe_id"],
                "category": p["category"],
                "severity": p["severity"],
                "remediation_checklist": json.dumps(p["remediation_checklist"]),
            }
            for p in SEED_SECURITY_POLICIES
        ]
        collection.add(ids=ids, documents=docs, metadatas=metas)

    print("\n[SUCCESS] ChromaDB pre-seeded successfully!")
    print("CWE Definitions Indexed: CWE-798, CWE-89, CWE-327, CWE-22, CWE-312")
    print("Corporate Policies Indexed: POL-SEC-01, POL-SEC-02, POL-SEC-03")


if __name__ == "__main__":
    main()

