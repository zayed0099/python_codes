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

@pytest.fixture(scope="session")
def access_token():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            client.post('/api/v1/signin', json={
                "username": "testuser_new",
                "password": "testpassword123_n"
            })
        response = client.post('/api/v1/login', json={
            "username": "testuser_new",
            "password": "testpassword123_n"
        })
        assert response.status_code in [200, 201]
        json_data = response.get_json()
        assert "access_token" in json_data
        return json_data["access_token"]

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
    assert response.status_code == 401
    data = response.get_json()
    assert "unsuccessful" in str(data).lower()

def test_login_wrong_username(client):
    response = client.post('/api/v1/login', json={
        "username" : "testuser_wrong",
        "password" : "testpassword124"
        })
    assert response.status_code == 404
    data = response.get_json()
    assert "error" in str(data).lower()

def test_post(client, access_token):
    response = client.post('/api/v1/books/', json={
        "title": "first book",
        "author": "first author"
    }, headers={
        "Authorization": f"Bearer {access_token}"
    })

    assert response.status_code == 201

    data = response.get_json()
    assert "title" in str(data).lower()
    assert "author" in str(data).lower()

def test_get(client, access_token):
    headers={
        "Authorization": f"Bearer {access_token}"
    }

    response = client.get('/api/v1/books/', headers=headers)

    assert response.status_code == 200
    data = response.get_json()
    assert "books" in str(data).lower()
    assert "page" in str(data).lower()

def test_get_specific(client, access_token):
    headers={
        "Authorization": f"Bearer {access_token}"
    }

    response = client.get('/api/v1/books/1', headers=headers)

    assert response.status_code == 200
    data = response.get_json()
    assert "title" in str(data).lower()

def test_put(client, access_token):
    headers={
        "Authorization": f"Bearer {access_token}"
    }

    response = client.put('/api/v1/books/1', json={
        "title": "first book updated",
        "author": "first author updated"
    }, headers=headers)

    assert response.status_code == 200
    data = response.get_json()
    assert 'successfully' in str(data).lower()

def test_delete(client, access_token):
    headers={
        "Authorization": f"Bearer {access_token}"
    }

    response = client.delete('/api/v1/books/1', headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert 'successfully' in str(data).lower()
