# Cryptic

This is a benchmarking and data-visualisation program for encryption libraries in C that measures:
- Runtime
- CPU Cycles per byte
- Throughput

## Usage:
1. Run 3-Data_Visualisation.ipynb
2. Modify and update the test scripts
3. Compile and run the relevant scripts
4. View results on 3-Data_Visualisation.ipynb once finished

## Example:
1. Run 3-Data_Visualisation.ipynb
2. While 3-Data_Visualisation.ipynb is running, run the following
```
cd 2.1-TestAES
gcc 2.1-TestAES aes.c -o output -ltomcrypt
./output
```
3. Check that data appears correctly in 3-Data_Visualisation.ipynb
