# run.py
import os
import sys

# Ensure project root is in sys.path (NOT security_scanner/)
project_root = os.path.dirname(os.path.abspath(__file__))  # SecurityAutomationScript
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Run the main module
from security_scanner.main import main

if __name__ == "__main__":
    main()
