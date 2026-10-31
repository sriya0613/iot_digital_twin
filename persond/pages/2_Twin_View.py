# Streamlit auto-adds this to the sidebar as "Twin View". Three lines: all logic is in twin_view.py.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import twin_view
twin_view.render()
