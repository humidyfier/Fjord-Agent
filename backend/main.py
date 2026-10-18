"""
backend/main.py
CLI entrypoint to launch the Fjord Command Center web application.
Enables running via:
    python -m backend.main
"""

import sys
import uvicorn

def main():
    uvicorn.run("backend.api.app:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    main()
