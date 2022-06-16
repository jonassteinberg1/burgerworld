import pytest
import requests

flask_url = "localhost"
flask_port = "5000"

def test_flask_root_returns_200():
     response = requests.get(f"http://{flask_url}:{flask_port}")
     assert response.status_code == 200
