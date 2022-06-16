import pytest
import requests

from requests.exceptions import ConnectionError

def is_responsive(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
    except ConnectionError:
        return False

def test_get_root_equals_200():
     response = requests.get("http://localhost:5000")
     assert response.status_code == 200
