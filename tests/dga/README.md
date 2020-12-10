# DGA detection testing workflow


## Overview 

nDPI provides a set of threat detection features available through NDPI_RISK detection.

As part of these features, we provide DGA detection.

Domain generation algorithms (DGA) are algorithms seen in various families of malware that are used
 to periodically generate a large number of domain names that can be used as rendezvous points with 
 their command and control servers.
 
DGA detection heuristic is implemented [**here**](https://github.com/ntop/nDPI/blob/328ff2465709372c595cb25d99135aa515da3c5a/src/lib/ndpi_main.c#L6729).

DGA performances test and tracking allows us to detect automatically if a modification is harmful.

The modification can be a simple threshold change or a future lightweight ML approach.

## Used data

Original used dataset is a collection of legit and DGA domains (balanced) that can be obtained as follows:

```shell
wget https://data.netlab.360.com/feeds/dga/dga.txt -O dga.csv
wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip -O non_dga.csv.zip
wget https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv -O complement.csv
```

We split the dataset into DGA and NON-DGA and we keep 10% of each as test set and 90% as training set.

```shell
python3 -m pip install pandas
python3 -m pip install sklearn
```

Instruction using python3

```python3
from sklearn.model_selection import train_test_split
import pandas as pd
seed=27 # Fix seed for reproducibility

df_dga = pd.read_csv("dga.csv", 
                     header=None, 
                     sep="\t", 
                     skip_blank_lines=True, 
                     comment='#', 
                     names=["type", "input", "start", "end"]).drop_duplicates().drop(['start', 'end', 'type'], 
                                                                                     axis=1)
df_dga["target"] = 1
df_non_dga = pd.read_csv("non_dga.csv.zip", compression="zip", header=None, names=["input"]).drop_duplicates()
df_non_dga["target"] = 0
df = pd.read_csv("complement.csv", header=None, names=["type", "family", "domain"])
df_dga_comp = df[df.type=="dga"]
df_non_dga_comp = df[df.type=="legit"]
df_non_dga_comp["target"] = 0
df_dga_comp["target"] = 1
df_dga_comp.rename(columns={'domain': 'input'}, inplace=True)
df_non_dga_comp.rename(columns={'domain': 'input'}, inplace=True)
df_dga_comp.drop(['type', 'family'], axis=1, inplace=True)
df_non_dga_comp.drop(['type', 'family'], axis=1, inplace=True)
df_dga = pd.concat([df_dga, df_dga_comp]).drop_duplicates()
df_non_dga = pd.concat([df_non_dga, df_non_dga_comp]).drop_duplicates()
sample_size = min(df_non_dga.shape[0], df_dga.shape[0])
df_dga = df_dga.sample(n=sample_size, random_state=seed)
df_non_dga = df_non_dga.sample(n=sample_size, random_state=seed)
train_non_dga, test_non_dga = train_test_split(df_non_dga, test_size=0.05, shuffle=True, random_state=27)
train_dga, test_dga = train_test_split(df_dga, test_size=0.05, shuffle=True, random_state=27)
train = pd.concat([train_non_dga, train_dga])
test = pd.concat([test_non_dga, test_dga])
test_dga["input"].to_csv("dga/test_dga.csv", header=False, index=False)
test_non_dga["input"].to_csv("dga/test_non_dga.csv", header=False, index=False)
train_dga["input"].to_csv("dga/train_dga.csv", header=False, index=False)
train_non_dga["input"].to_csv("dga/train_non_dga.csv", header=False, index=False)
```

**Detection approach must be built on top of training set only, test set must be kept as unseen cases for testing**

## dga_evaluate

After nDPI compilation, you can use dga_evaluate helper to check number of detections out of an input file.

```shell
dga_evaluate <file name>
```

You can evaluate your modifications performances before submitting it as follows:

```shell
./do-dga.sh
```

If your modifications decreases baseline performances, test will fails.
If not (well done), test passed and you must update the baseline metrics with your obtained ones.