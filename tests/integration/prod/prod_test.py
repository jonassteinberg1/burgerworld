import pytest
import os
import requests

def test_nginx_root_returns_200():
     response = requests.get(f"http://{os.getenv('NGINX_URL')}:{os.getenv('NGINX_PORT')}")
     assert response.status_code == 200
