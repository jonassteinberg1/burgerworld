import pytest
import os
import requests

def test_flask_root_returns_200():
     response = requests.get(f"http://{os.getenv('FLASK_URL')}:{os.getenv('FLASK_PORT')}")
     assert response.status_code == 200
