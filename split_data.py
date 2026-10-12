import pandas as pd
from m1_capture.splits import session_time_split

df = pd.read_parquet('data/features.parquet')
train, val = session_time_split(df, time_col='t', label_col='role', val_frac=0.2)

# Split train into model-train (sessions 2b,3b,4c) and calibration (sessions 6d,6e,6f,6g,6h)
model_train = train[train['session'].isin(['2b', '3b', '4c'])]
calibration = train[train['session'].isin(['6d', '6e', '6f', '6g', '6h'])]

# Save all three partitions
model_train.to_csv('data/X_train.csv', index=False)
(model_train['y'].to_frame('y')).to_csv('data/y_train.csv', index=False)

calibration.to_csv('data/X_cal.csv', index=False)
(calibration['y'].to_frame('y')).to_csv('data/y_cal.csv', index=False)

val.to_csv('data/X_val.csv', index=False)
(val['y'].to_frame('y')).to_csv('data/y_val.csv', index=False)

print('All CSVs generated successfully')
print()
print('Model train:')
print(f'  Sessions: {sorted(model_train["session"].unique())}')
print(f'  Rows: {len(model_train)}')
print(f'  Benign: {int((model_train["y"]==0).sum())}, Attack: {int((model_train["y"]==1).sum())}')
print(f'  Entities: {model_train["entity"].nunique()}')
print()
print('Calibration:')
print(f'  Sessions: {sorted(calibration["session"].unique())}')
print(f'  Rows: {len(calibration)}')
print(f'  Benign: {int((calibration["y"]==0).sum())}, Attack: {int((calibration["y"]==1).sum())}')
print(f'  Entities: {calibration["entity"].nunique()}')
print()
print('Validation (untouched):')
print(f'  Sessions: {sorted(val["session"].unique())}')
print(f'  Rows: {len(val)}')
print(f'  Benign: {int((val["y"]==0).sum())}, Attack: {int((val["y"]==1).sum())}')