import sys
sys.path.insert(0, "src")

from dashboard.server import serve

if __name__ == "__main__":
    serve()