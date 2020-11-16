#!/bin/sh

cd "$(dirname "${0}")"

# Baseline performances ------------------------------------------------------------------------------------------------
# Important notes: BASE values must be integers examples and represents percentage (e.g. 79%, 98%).
BASE_ACCURACY=66
BASE_PRECISION=86
BASE_RECALL=38
# ----------------------------------------------------------------------------------------------------------------------

DGA_EVALUATE="./dga/dga_evaluate"
DGA_DATA="dga/test_dga.csv"
NON_DGA_DATA="dga/test_non_dga.csv"
DGA_DATA_SIZE=0
NON_DGA_DATA_SIZE=0
DATA_SIZE=0
RC=0

get_evaluation_data_size() {
  DGA_DATA_SIZE=`wc -l dga/test_dga.csv | awk '{split($0,a," "); print a[1]}'`
  NON_DGA_DATA_SIZE=`wc -l dga/test_non_dga.csv | awk '{split($0,a," "); print a[1]}'`
  DATA_SIZE=$(( $NON_DGA_DATA_SIZE + $DGA_DATA_SIZE ))
}

evaluate_ndpi_dga_detection() {
  # DGA detection is a binary classification problem, We evaluate the following metrics:
  # Accuracy: (TP + TN) / (TP + TN + FN + FP)
  # Precision: TP / (TP + FP)
  # Recall: TP / (TP + FN)

  TP=`$DGA_EVALUATE dga/test_dga.csv`
  FN=$(( $DGA_DATA_SIZE - $TP ))
  FP=`$DGA_EVALUATE dga/test_non_dga.csv`
  TN=$(( $NON_DGA_DATA_SIZE - $FP ))

  ACCURACY=`echo "print(int(((${TP} + ${TN})/(${TP} + ${TN} + ${FP} + ${FN}))*100))" | python3`
  PRECISION=`echo "print(int(((${TP})/(${TP} + ${FP}))*100))" | python3`
  RECALL=`echo "print(int(((${TP})/(${TP} + ${FN}))*100))" | python3`

  # In case modified version of classification algorithm decreases performances, test do not pass.
  if [ $ACCURACY -lt $BASE_ACCURACY ]; then
		 printf "ERROR: Your modifications decreased DGA classifier accuracy: 0.${BASE_ACCURACY} decreased to 0.${ACCURACY}!\n"
		 RC=1
  fi
  if [ $PRECISION -lt $BASE_PRECISION ]; then
		 printf "ERROR: Your modifications decreased DGA classifier precision: 0.${BASE_PRECISION} decreased to 0.${PRECISION}!\n"
		 RC=1
  fi
  if [ $RECALL -lt $BASE_RECALL ]; then
		 printf "ERROR: Your modifications decreased DGA classifier recall: 0.${BASE_RECALL} decreased to 0.${RECALL}!\n"
		 RC=1
  fi

  # Finally we print the current performances, upgrade BASE_ metrics in case you improved it.
  echo "DGA detection performances report:"
  echo "Accuracy=0.$ACCURACY"
  echo "Precision=0.$PRECISION"
  echo "Recall=0.$RECALL"
}

get_evaluation_data_size
evaluate_ndpi_dga_detection

exit $RC
