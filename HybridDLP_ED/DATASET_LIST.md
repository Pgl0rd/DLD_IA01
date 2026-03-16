# 📊 Dataset List for DLP Model Training

**Purpose:** Training Machine Learning models for Data Loss Prevention (DLP) system

---

## 🎯 Recommended Datasets

### **1. CMU CERT Insider Threat Dataset** ⭐⭐⭐⭐⭐
**Best for:** Behavioral analysis, insider threat detection

- **Link:** https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
- **Description:** Comprehensive dataset from Carnegie Mellon University containing user activity logs, file access patterns, and insider threat scenarios
- **Size:** ~2.5GB
- **Format:** CSV, JSON
- **Use Cases:**
  - User behavior analysis
  - Anomaly detection
  - File access pattern recognition
  - Time-based activity analysis
- **License:** Research use
- **Pros:**
  - Real-world scenarios
  - Multiple data types (file, network, email)
  - Labeled threat scenarios
- **Cons:**
  - Large size
  - Requires preprocessing

---

### **2. SASE Toolbox DLP Sample Files** ⭐⭐⭐⭐
**Best for:** Sensitive data patterns, PII detection

- **Link:** https://www.sasetoolbox.com/dlp-sample-files.html
- **Description:** Sample files containing various types of sensitive data (credit cards, SSN, emails, etc.)
- **Format:** Text files, CSV, Excel
- **Use Cases:**
  - Pattern recognition
  - YARA rule validation
  - PII detection training
- **License:** Free for research
- **Pros:**
  - Real sensitive data patterns
  - Multiple data types
  - Easy to use
- **Cons:**
  - Limited size
  - May need more samples

---

### **3. Nightfall AI Sample Data** ⭐⭐⭐⭐
**Best for:** Policy templates, sensitive data examples

- **Link:** https://help.nightfall.ai/nightfall_policy_templates/sample_data
- **Description:** Sample data for DLP policy testing and training
- **Format:** JSON, CSV
- **Use Cases:**
  - Policy validation
  - Pattern matching
  - Risk scoring
- **License:** Free
- **Pros:**
  - Well-structured
  - Multiple categories
  - Policy-aligned
- **Cons:**
  - Limited to samples

---

### **4. Enron Email Dataset** ⭐⭐⭐
**Best for:** Email content analysis, communication patterns

- **Link:** https://www.cs.cmu.edu/~enron/
- **Description:** Large collection of real emails from Enron corporation
- **Size:** ~500MB
- **Format:** Email files
- **Use Cases:**
  - Email content classification
  - Communication pattern analysis
  - Sensitive information in emails
- **License:** Public domain
- **Pros:**
  - Real-world emails
  - Large volume
  - Natural language
- **Cons:**
  - Requires labeling
  - Privacy concerns

---

### **5. Kaggle Credit Card Fraud Detection** ⭐⭐⭐
**Best for:** Financial data patterns, anomaly detection

- **Link:** https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
- **Description:** Credit card transaction data with fraud labels
- **Size:** ~150MB
- **Format:** CSV
- **Use Cases:**
  - Financial data patterns
  - Anomaly detection
  - Risk scoring
- **License:** Open Database License
- **Pros:**
  - Labeled data
  - Real transactions
  - Good for ML training
- **Cons:**
  - Focused on fraud, not DLP
  - Requires adaptation

---

### **6. PII Dataset (Synthetic)** ⭐⭐⭐
**Best for:** PII detection, pattern recognition

- **Link:** https://github.com/microsoft/presidio (with sample data)
- **Description:** Synthetic PII data for training detection models
- **Format:** JSON, CSV
- **Use Cases:**
  - PII detection
  - Named entity recognition
  - Pattern matching
- **License:** MIT
- **Pros:**
  - Well-structured
  - Multiple PII types
  - Easy to use
- **Cons:**
  - Synthetic (not real)
  - Limited size

---

### **7. WikiText Dataset** ⭐⭐⭐
**Best for:** Normal document baseline, text classification

- **Link:** https://www.salesforce.com/products/einstein/ai-research/the-wikitext-dependency-language-modeling-dataset/
- **Description:** Large collection of Wikipedia articles
- **Size:** ~100MB
- **Format:** Text
- **Use Cases:**
  - Normal document baseline
  - Text classification
  - Contrast with sensitive data
- **License:** Creative Commons
- **Pros:**
  - Large volume
  - Clean text
  - Good baseline
- **Cons:**
  - Not sensitive data
  - Requires labeling

---

### **8. Financial Documents Dataset** ⭐⭐⭐
**Best for:** Financial data detection, document classification

- **Link:** Various sources (need to compile)
- **Description:** Financial reports, invoices, bank statements (synthetic or anonymized)
- **Format:** PDF, Text, CSV
- **Use Cases:**
  - Financial data detection
  - Document classification
  - Amount pattern recognition
- **License:** Varies
- **Pros:**
  - Domain-specific
  - Real patterns
- **Cons:**
  - Hard to find public datasets
  - May need to create synthetic

---

## 🎯 Dataset Categories

### **A. Sensitive Data Patterns**
- SASE Toolbox DLP Sample Files
- Nightfall AI Sample Data
- PII Dataset (Synthetic)

### **B. Behavioral Analysis**
- CMU CERT Insider Threat Dataset
- Enron Email Dataset

### **C. Normal Document Baseline**
- WikiText Dataset
- Wikipedia articles (via API)

### **D. Financial Data**
- Kaggle Credit Card Fraud Detection
- Financial Documents (synthetic)

---

## 📋 Recommended Approach

### **Phase 1: Pattern Recognition (YARA + ML)**
1. **SASE Toolbox** - For sensitive data patterns
2. **Nightfall AI** - For policy templates
3. **Synthetic PII** - For training detection

### **Phase 2: Document Classification**
1. **WikiText** - Normal documents baseline
2. **Synthetic sensitive documents** - Created from templates
3. **Mix and label** - Create balanced dataset

### **Phase 3: Behavioral Analysis (Future)**
1. **CMU CERT** - For user behavior
2. **Enron Email** - For communication patterns

---

## 🔧 How to Use

### **1. Download Datasets**
```bash
# Create dataset directory
mkdir -p worker/dataset/{sensitive,normal,behavioral}

# Download CMU CERT (if needed)
# wget https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247

# Download SASE Toolbox samples
# Visit: https://www.sasetoolbox.com/dlp-sample-files.html
```

### **2. Prepare Data**
```bash
# Use existing script
python worker/scripts/collect_dataset.py

# Or create custom script
python worker/scripts/prepare_dataset.py --source sase --output dataset/sensitive/
```

### **3. Train Model**
```bash
python worker/scripts/train_model.py --dataset dataset/ --output ml_models/
```

---

## 📝 Notes

1. **Privacy & Ethics:**
   - Use synthetic data when possible
   - Anonymize real data
   - Follow data protection regulations

2. **Data Quality:**
   - Balance between sensitive and normal
   - Include edge cases
   - Validate with YARA rules

3. **Legal Compliance:**
   - Check dataset licenses
   - Ensure GDPR/NDPR compliance
   - Use only for research/training

---

## 🚀 Quick Start

**Recommended for immediate use:**
1. **SASE Toolbox** - Quick start, real patterns
2. **Synthetic generation** - Use `collect_dataset.py`
3. **WikiText** - For normal baseline

**For advanced training:**
1. **CMU CERT** - Comprehensive behavioral data
2. **Custom synthetic** - Tailored to your needs

---

## 📚 Additional Resources

- **Presidio (Microsoft):** https://github.com/microsoft/presidio
- **DLP Research Papers:** Search on Google Scholar
- **Kaggle Datasets:** https://www.kaggle.com/datasets (search "PII", "sensitive data")
- **UCI ML Repository:** https://archive.ics.uci.edu/ (various datasets)
- **GitHub DLP Projects:** Search "data loss prevention dataset"
- **VirusTotal:** https://www.virustotal.com (for malware patterns, not direct dataset)

---

## 🎯 Quick Start Recommendation

**For immediate training (recommended order):**

1. **Start with synthetic data** (using `collect_dataset.py`)
   - Fast to generate
   - Controlled patterns
   - Good for initial training

2. **Add SASE Toolbox samples**
   - Real patterns
   - Quick download
   - Validate with YARA

3. **Use WikiText for baseline**
   - Normal documents
   - Large volume
   - Free and accessible

4. **Scale with CMU CERT** (if needed)
   - Comprehensive
   - Real-world scenarios
   - Advanced training

---

## 📝 Usage in This Project

### **Current Script:**
```bash
# Generate synthetic dataset
python worker/scripts/collect_dataset.py

# This creates:
# - dataset/sensitive/ (synthetic sensitive documents)
# - dataset/normal/ (Wikipedia articles)
# - dataset/labels.json (auto-labeling)
```

### **Next Steps:**
1. Download additional datasets from recommended sources
2. Merge with synthetic data
3. Train model: `python worker/scripts/train_model.py`

---

**Last Updated:** 2026-02-28
