import sys, os, hashlib
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))
sys.path.insert(0, os.path.abspath("./m3_scraping" if False else "./m3_scoring"))

import pandas as pd, numpy as np
from m1_capture.features import FEATURE_ORDER
from m3_scoring.train_xgb import train
from m3_scoring.calibrate import calibrate, CalibrationResult
from sklearn.metrics import average_precision_score, roc_auc_score, confusion_matrix

X_train = pd.read_csv('data/X_train.csv')[FEATURE_ORDER]
y_train = pd.read_csv('data/y_train.csv').squeeze("columns")
X_cal   = pd.read_csv('data/X_cal.csv')[FEATURE_ORDER]
y_cal   = pd.read_csv('data/y_cal.csv').squeeze("columns")
X_val   = pd.read_csv('data/X_val.csv')[FEATURE_ORDER]
y_val   = pd.read_csv('data/y_val.csv').squeeze("columns")

print("DATA SPLIT (data/ - current generated CSVs):")
print(f"  Train: {X_train.shape}  benign={(y_train==0).sum()} attack={(y_train==1).sum()}")
print(f"  Cal  : {X_cal.shape}    benign={(y_cal==0).sum()}   attack={(y_cal==1).sum()}")
print(f"  Val  : {X_val.shape}    benign={(y_val==0).sum()}   attack={(y_val==1).sum()}")
print(f"  Total={len(X_train)+len(X_cal)+len(X_val)} rows | session-level (A-D train, E cal, F-G val)")

print("\nTraining XGBoost...")
model = train(X_train, y_train, X_val, y_val)

print("\nCalibrating (Isotonic on held-out cal)...")
result = calibrate(model, X_cal, y_cal)

raw = model.predict_proba(X_val)[:, 1]
cal = np.array([result.calibrated_score(dict(zip(FEATURE_ORDER, row))) for row in X_val.values])
thr=0.5
def m(y,s):
    p=(s>=thr).astype(int)
    tn,fp,fn,tp=confusion_matrix(y,p).ravel()
    return dict(pr_auc=float(average_precision_score(y,s)), roc_auc=float(roc_auc_score(y,s)),
                precision=float(tp/(tp+fp)) if tp+fp else 0, recall=float(tp/(tp+fn)) if tp+fn else 0,
                f1=float(2*(tp/(tp+fp))*(tp/(tp+fn))/((tp/(tp+fp))+(tp/(tp+fn)))) if (tp+fp) and (tp+fn) else 0,
                fpr=float(fp/(fp+tn)) if fp+tn else 0, tp=int(tp),fp=int(fp),fn=int(fn),tn=int(tn))
rm= m(y_val,raw); cm=m(y_val,cal)
def ece(y,s):
    total=len(y); out=0.0; edges=np.linspace(0,1,11)
    for i in range(10):
        mm=(s>edges[i])&(s<=edges[i+1])
        if mm.sum()>0: out+=(mm.sum()/total)*abs(float(s[mm].mean())-float(y[mm].mean()))
    return float(out)
print("\nHELD-OUT VALIDATION (threshold 0.5):")
print(f"{'metric':<12} | {'raw':>10} | {'calibrated':>10}")
print("-"*38)
for k in ["pr_auc","roc_auc","precision","recall","f1","fpr"]:
    print(f"{k:<12} | {rm[k]:>10.6f} | {cm[k]:>10.6f}")
print(f"ece  | {ece(y_val,raw):>10.6f} | {ece(y_val,cal):>10.6f}")
print(f"\nconfusion raw: TP={rm['tp']} FP={rm['fp']} FN={rm['fn']} TN={rm['tn']}")
print(f"          cal: TP={cm['tp']} FP={cm['fp']} FN={cm['fn']} TN={cm['tn']}")

out='calibration_result_current.joblib'
result.save(out)
print(f"\nSaved: {out}  ({os.path.getsize(out)} bytes)")
print(f"sha256: {hashlib.sha256(open(out,'rb').read()).hexdigest()}")
print("DONE")
