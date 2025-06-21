import pytest
from main_file import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client

def test_signup_success(client):
    response = client.post('/api/v1/signin', json={
        "username" : "testuser",
        "password" : "testpassword123"
        })
    assert response.status_code == 200
    data = response.get_json()
    assert "successful" in str(data).lower()

def test_signup_no_data(client):
    response = client.post('/api/v1/signin', json={})
    assert response.status_code == 400
    data = response.get_json()
    assert "missing" in str(data).lower()

def test_signup_missing_password(client):
    response = client.post('/api/v1/signin', json={
        "username" : "testuser_wo_pass",
        })
    assert response.status_code == 400
    data = response.get_json()
    assert "validation_errors" in str(data).lower()

def test_login_success(client):
    response = client.post('/api/v1/login', json={
        "username" : "testuser",
        "password" : "testpassword123"
        })
    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in str(data).lower()

def test_login_missing_password(client):
    response = client.post('/api/v1/login', json={
        "username" : "testuser"
        })
    assert response.status_code == 400
    data = response.get_json()
    assert "validation_errors" in str(data).lower()

def test_login_wrong_password(client):
    response = client.post('/api/v1/login', json={
        "username" : "testuser",
        "password" : "testpassword124"
        })
    assert response.status_code in [401, 404]
    data = response.get_json()
    assert "unsuccessful" in str(data).lower()