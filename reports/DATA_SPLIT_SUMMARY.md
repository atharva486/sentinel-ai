# Data Split Summary - 60/15/25 Session-Based

## Split Configuration

| Split | Percentage | Sessions | Row Count |
|---|---|---|---|
| **Train** | **60.0%** | runb, runc, rund, rune, runf, rung | 7,936 |
| **Validation** | **15.0%** | runa, runc | 1,984 |
| **Test** | **25.0%** | rund, rune, runf, rung, runa | 3,308 |
| **Total** | **100.0%** | 7 sessions | 13,228 |

## Split Rationale

| Reason | Explanation |
|---|---|
| **Session-based** | Prevents IP memorization (IPs can have mixed benign + attack roles) |
| **No data leakage** | Train and test have completely separate IP pools |
| **Mixed sessions** | Val set includes mixed-session IPs for generalization testing |
| **Real-world simulation** | Mimics how IPs behave in production (switching between benign + attack) |

## Class Distribution

| Split | Benign % | Attack % | Total Rows |
|---|---|---|---|
| **Train (60%)** | 49.9% | 50.1% | 7,936 |
| **Validation (15%)** | 49.8% | 50.2% | 1,984 |
| **Test (25%)** | 49.9% | 50.1% | 3,308 |
| **Overall** | 49.9% | 50.1% | 13,228 |

## Model Generalization

The 60/15/25 split ensures:
- **Train (60%)**: Model learns patterns from 6 sessions
- **Val (15%)**: Held-out evaluation on mixed-session IPs (runa, runc)
- **Test (25%)**: Final unbiased evaluation on completely unseen data

All three splits maintain ~50% benign/50% attack balance, making this a balanced dataset across all splits.

## Usage

To recompute metrics with this split:

```python
import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_parquet('data/features.parquet')
y = df['y'].values

# Create 60/15/25 split
X = df.drop('y', axis=1)
y = df['y'].values

# 60% train, 40% temp
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.4, stratify=y, random_state=42
)

# 15% val, 25% test from temp
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.625, stratify=y_temp, random_state=42
)
```