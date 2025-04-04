import sqlite3
import pandas as pd
import numpy as np
import pyshark
import sklearn
import flask

print("✅ SQLite connected:", sqlite3.connect(":memory:"))
print("✅ Pandas version:", pd.__version__)
print("✅ NumPy version:", np.__version__)
print("✅ Scikit-learn version:", sklearn.__version__)
print("✅ Flask version:", flask.__version__)
print("✅ PyShark test:", pyshark.LiveCapture(interface="Wi-Fi"))
