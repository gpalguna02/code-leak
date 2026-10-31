"""ChromaDB persistent vector database setup and policy retrieval engine."""

import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import CHROMA_DB_PATH

# Standard CWE Knowledge Base and Corporate Security Policies
SEED_SECURITY_POLICIES = [
    {
        "id": "CWE-798",
        "title": "CWE-798: Use of Hard-coded Credentials",
        "category": "CWE",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "document": (
            "CWE-798 Use of Hard-coded Credentials: The software contains hard-coded credentials, "
            "such as an API key, private key, token, or database password. "
            "Exposed keys in source control can be extracted by attackers and used to compromise infrastructure. "
            "Remediation: Invalidate and rotate the exposed credential immediately. "
            "Store secrets in environment variables (.env excluded via .gitignore) or local/cloud secrets managers "
            "(AWS Secrets Manager, HashiCorp Vault). Use git-filter-repo to purge keys from Git history."
        ),
        "remediation_checklist": [
            "Immediately revoke/rotate the compromised secret in provider dashboard (AWS, GitHub, Stripe).",
            "Migrate credential to local environment variables (.env) or Vault secrets manager.",
            "Verify .gitignore includes .env, *.pem, and local credentials files.",
            "Run git-filter-repo or git-rebase to purge secret commit from git history.",
        ],
    },
    {
        "id": "CWE-89",
        "title": "CWE-89: SQL Injection",
        "category": "CWE",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "document": (
            "CWE-89 SQL Injection: Untrusted user input is directly concatenated, formatted, or interpolated "
            "into a database query string before execution. Attackers can bypass authentication, view private records, "
            "or drop entire database tables. "
            "Remediation: Always use parameterized queries (prepared statements) or ORM parameter binding. "
            "Never construct SQL via f-strings or '+' string concatenation."
        ),
        "remediation_checklist": [
            "Refactor raw SQL strings to use parameterized query placeholders (%s or ?).",
            "Ensure user inputs are never formatted directly into SQL query templates.",
            "Use ORM query builders (e.g. SQLAlchemy, Prisma) with native parameter sanitization.",
            "Conduct automated SQL injection vulnerability test before merge.",
        ],
    },
    {
        "id": "CWE-327",
        "title": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "category": "CWE",
        "cwe_id": "CWE-327",
        "severity": "HIGH",
        "document": (
            "CWE-327 Broken or Risky Cryptographic Algorithm: The application utilizes deprecated or weak algorithms "
            "such as MD5, SHA-1, DES, RC4, or ECB block cipher mode. These algorithms possess known cryptographic "
            "weaknesses, collision attacks, and can be broken with minimal compute. "
            "Remediation: Upgrade hashing algorithms to SHA-256 / SHA-3 for digest integrity, Argon2id/bcrypt "
            "for password hashing, and AES-GCM (256-bit) with authenticated encryption for symmetric data."
        ),
        "remediation_checklist": [
            "Replace hashlib.md5 and hashlib.sha1 with hashlib.sha256 or hashlib.sha3_256.",
            "Use Argon2id or bcrypt with high work factor for user password storage.",
            "Replace ECB cipher mode with authenticated Galois/Counter Mode (AES-GCM).",
            "Audit all cryptographic primitives against modern NIST SP 800-131A standards.",
        ],
    },
    {
        "id": "CWE-22",
        "title": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "category": "CWE",
        "cwe_id": "CWE-22",
        "severity": "CRITICAL",
        "document": (
            "CWE-22 Path Traversal: The application constructs file paths using external input without verifying "
            "that the path resolves within the intended directory. Attackers can provide '../' sequences to read "
            "or overwrite sensitive system files like /etc/passwd or application source files. "
            "Remediation: Normalize path using os.path.abspath and verify with os.path.commonpath that the resulting "
            "canonical path starts with the trusted root folder."
        ),
        "remediation_checklist": [
            "Resolve canonical path using os.path.realpath / os.path.abspath.",
            "Verify that target file path starts strictly with the designated storage root folder.",
            "Reject user-supplied path strings containing '..' or directory separators.",
            "Consider mapping user input to an internal UUID or whitelist instead of raw filenames.",
        ],
    },
    {
        "id": "CWE-312",
        "title": "CWE-312: Cleartext Storage of Sensitive Information",
        "category": "CWE",
        "cwe_id": "CWE-312",
        "severity": "HIGH",
        "document": (
            "CWE-312 Cleartext Storage / Transmission: Confidential data such as passwords, access tokens, API keys, "
            "or PII are stored or transmitted in plaintext (e.g., printed in application logs, transmitted over unencrypted HTTP, "
            "or saved in unencrypted config files). "
            "Remediation: Implement automatic log masking for authentication tokens and credentials. "
            "Enforce TLS 1.3 for all transport and encrypt sensitive database columns at rest."
        ),
        "remediation_checklist": [
            "Add filter to logging pipeline to mask authorization tokens and passwords before printing.",
            "Ensure sensitive URLs use HTTPS with strict transport security (HSTS).",
            "Store sensitive configurations encrypted at rest using local secret stores.",
            "Conduct review of all print/console.log statements in production code.",
        ],
    },
    {
        "id": "POL-SEC-01",
        "title": "POL-SEC-01: Zero Credential Commit Policy",
        "category": "COMPANY_POLICY",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "document": (
            "Internal DevSecOps Policy POL-SEC-01: No plaintext credentials, private keys, cloud tokens, or API secrets "
            "are permitted in any Git branch. Pre-commit hooks must block commits containing high-entropy keys. "
            "CI/CD pipelines must immediately fail builds upon detection of credentials."
        ),
        "remediation_checklist": [
            "Ensure pre-commit scanner is installed and active in local repo.",
            "Adopt central secret manager for development and production environments.",
        ],
    },
    {
        "id": "POL-SEC-02",
        "title": "POL-SEC-02: Cryptographic Standards Policy",
        "category": "COMPANY_POLICY",
        "cwe_id": "CWE-327",
        "severity": "HIGH",
        "document": (
            "Internal DevSecOps Policy POL-SEC-02: Legacy cryptographic algorithms (MD5, SHA-1, DES, RC4) are prohibited "
            "in production systems. All cryptographic operations must use approved algorithms: SHA-256, AES-256-GCM, "
            "or Ed25519."
        ),
        "remediation_checklist": [
            "Verify all crypto operations conform to POL-SEC-02 approved algorithm matrix.",
        ],
    },
    {
        "id": "POL-SEC-03",
        "title": "POL-SEC-03: Parameterized SQL & Safe Data Access Policy",
        "category": "COMPANY_POLICY",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "document": (
            "Internal DevSecOps Policy POL-SEC-03: Direct SQL string concatenation and dynamic string interpolation "
            "are forbidden across all database drivers. All database operations must enforce bind parameters."
        ),
        "remediation_checklist": [
            "Run static code analysis to verify 100% prepared query compliance.",
        ],
    },
]


def _tokenize(text: str) -> List[str]:
    """Tokenizes text into lowercase words/terms."""
    return re.findall(r"\b[a-zA-Z0-9_\-]{2,}\b", text.lower())


def _compute_tf_vector(text: str) -> Dict[str, float]:
    """Computes a normalized term-frequency vector."""
    tokens = _tokenize(text)
    if not tokens:
        return {}
    counts: Dict[str, float] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in counts.values()))
    if norm == 0.0:
        return counts
    return {k: v / norm for k, v in counts.items()}


def _cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
    """Computes cosine similarity between two normalized sparse term vectors."""
    score = 0.0
    for k, v in vec1.items():
        if k in vec2:
            score += v * vec2[k]
    return score


class LocalPersistentVectorStore:
    """
    Lightweight, robust, zero-dependency persistent vector database engine
    providing a ChromaDB-compatible interface.
    Persists data to `./backend/data/chroma_db/collection_cwe_policies.json`.
    """

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.file_path = self.storage_path / "collection_cwe_policies.json"
        self.documents: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            pass
        if self.file_path.exists():
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    self.documents = json.load(f)
            except Exception:
                self.documents = {}
        else:
            self.seed_defaults()

    def save(self) -> None:
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(self.documents, f, indent=2)
        except (OSError, PermissionError):
            pass

    def seed_defaults(self) -> None:
        for item in SEED_SECURITY_POLICIES:
            doc_id = item["id"]
            doc_text = item["document"]
            vec = _compute_tf_vector(doc_text)
            self.documents[doc_id] = {
                "id": doc_id,
                "document": doc_text,
                "metadata": {
                    "title": item["title"],
                    "cwe_id": item["cwe_id"],
                    "category": item["category"],
                    "severity": item["severity"],
                    "remediation_checklist": json.dumps(item["remediation_checklist"]),
                },
                "vector": vec,
            }
        self.save()

    def add(self, ids: List[str], documents: List[str], metadatas: List[Dict[str, Any]]) -> None:
        for doc_id, doc, meta in zip(ids, documents, metadatas):
            self.documents[doc_id] = {
                "id": doc_id,
                "document": doc,
                "metadata": meta,
                "vector": _compute_tf_vector(doc),
            }
        self.save()

    def query(self, query_texts: List[str], n_results: int = 3) -> Dict[str, Any]:
        """Queries the vector store and returns top matches ranked by cosine similarity."""
        results_docs = []
        results_metas = []
        results_distances = []
        results_ids = []

        for q in query_texts:
            q_vec = _compute_tf_vector(q)
            scored: List[Tuple[float, str, Dict[str, Any]]] = []

            for doc_id, data in self.documents.items():
                sim = _cosine_similarity(q_vec, data["vector"])
                # Boost if exact CWE tag is present in query
                cwe_tag = data["metadata"].get("cwe_id", "").lower()
                if cwe_tag and cwe_tag in q.lower():
                    sim += 0.5
                scored.append((sim, doc_id, data))

            scored.sort(key=lambda x: x[0], reverse=True)
            top = scored[:n_results]

            q_ids = [item[1] for item in top]
            q_docs = [item[2]["document"] for item in top]
            q_metas = [item[2]["metadata"] for item in top]
            q_dists = [round(max(0.0, 1.0 - item[0]), 3) for item in top]

            results_ids.append(q_ids)
            results_docs.append(q_docs)
            results_metas.append(q_metas)
            results_distances.append(q_dists)

        return {
            "ids": results_ids,
            "documents": results_docs,
            "metadatas": results_metas,
            "distances": results_distances,
        }

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self.documents.values())


# Module-level singleton vector store
_vector_store: Optional[Any] = None


def get_vector_collection(chroma_dir: Optional[Path] = None):
    """
    Returns the vector collection instance.
    Uses real chromadb if installed, else uses LocalPersistentVectorStore.
    """
    global _vector_store
    target_dir = chroma_dir or CHROMA_DB_PATH

    if _vector_store is not None:
        return _vector_store

    try:
        import chromadb  # type: ignore

        client = chromadb.PersistentClient(path=str(target_dir))
        collection = client.get_or_create_collection(name="cwe_security_policies")
        # Check if already seeded
        if collection.count() == 0:
            ids = [p["id"] for p in SEED_SECURITY_POLICIES]
            docs = [p["document"] for p in SEED_SECURITY_POLICIES]
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
        _vector_store = collection
        return _vector_store
    except Exception:
        # Fallback to local persistent vector store
        store = LocalPersistentVectorStore(target_dir)
        _vector_store = store
        return _vector_store


def retrieve_policies_for_findings(cwe_list: List[str], finding_titles: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
    """
    Retrieves relevant CWE policies and corporate rules matching the detected findings.
    """
    collection = get_vector_collection()
    query_str = " ".join(cwe_list) + " " + " ".join(finding_titles)
    if not query_str.strip():
        query_str = "security policy credentials sql injection crypto traversal"

    results = collection.query(query_texts=[query_str], n_results=top_k)

    policies = []
    if results and "ids" in results and results["ids"]:
        ids = results["ids"][0]
        docs = results["documents"][0]
        metas = results["metadatas"][0]
        distances = results.get("distances", [[0.0] * len(ids)])[0]

        for p_id, doc, meta, dist in zip(ids, docs, metas, distances):
            # Parse remediation checklist from JSON if needed
            checklist_raw = meta.get("remediation_checklist", "[]")
            try:
                checklist = json.loads(checklist_raw) if isinstance(checklist_raw, str) else checklist_raw
            except Exception:
                checklist = []

            policies.append({
                "id": p_id,
                "title": meta.get("title", p_id),
                "cwe_id": meta.get("cwe_id", ""),
                "category": meta.get("category", "CWE"),
                "severity": meta.get("severity", "HIGH"),
                "document": doc,
                "relevance_score": round(max(0.1, 1.0 - float(dist)), 2),
                "remediation_checklist": checklist,
            })

    return policies

