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

Original used dataset is a collection of legit and DGA domains (balanced) that can be obtained as follow:

```shell
wget https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv
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

df = pd.read_csv("dga_domains_full.csv", header=None, names=["type", "family", "domain"])
df_dga = df[df.type=="dga"]
df_non_dga = df[df.type=="legit"]
train_non_dga, test_non_dga = train_test_split(df_non_dga, test_size=0.1, shuffle=True, random_state=27)
train_dga, test_dga = train_test_split(df_dga, test_size=0.1, shuffle=True, random_state=27)

test_dga["domain"].to_csv("test_dga.csv", header=False, index=False)
test_non_dga["domain"].to_csv("test_non_dga.csv", header=False, index=False)
train_dga["domain"].to_csv("train_dga.csv", header=False, index=False)
test_non_dga["domain"].to_csv("test_non_dga.csv", header=False, index=False)
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