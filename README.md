# SecureAuth API – JWT Authentication & Role-Based Access Control

## About the Project

This project is developed using Python and FastAPI to implement a secure user authentication system with JWT (JSON Web Token).

It allows users to register, log in, access their profiles and use protected API endpoints. It also includes Role-Based Access Control (RBAC), where different permissions are provided to normal users and administrators.

## Features

- User registration with username, email and password.
- Password hashing using bcrypt.
- User login with credential verification.
- JWT access token generation and validation.
- OAuth2 authentication using Bearer tokens.
- Protected API endpoints.
- Retrieve the currently logged-in user's profile.
- Role-Based Access Control for Admin and Normal Users.
- SQLite database for storing user information.

## Technologies Used

- Python
- FastAPI
- SQLite
- Pydantic
- Passlib
- Bcrypt
- Python-JOSE (JWT)
- OAuth2

## Project Structure

```text
SecureAuth_API/
│
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
└── .env.example
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/shrinivasnaik27/SecureAuth-API.git
```

### 2. Open the Project Folder

```bash
cd SecureAuth-API
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

For Windows:

```bash
venv\Scripts\activate
```

### 5. Install Required Packages

```bash
pip install -r requirements.txt
```

### 6. Configure Environment Variables

For Windows PowerShell:

```powershell
$env:SECRET_KEY = "your-secret-key"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_EMAIL = "admin@example.com"
$env:ADMIN_PASSWORD = "your-admin-password"
```

Use your own strong credentials. Do not upload actual secrets to GitHub.

### 7. Run the Application

```bash
uvicorn main:app --reload
```

The application will start at:

http://127.0.0.1:8000

## API Documentation and Testing

FastAPI provides interactive API documentation through Swagger UI.

Open the following URL in your browser:

http://127.0.0.1:8000/docs

### Available API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Welcome message |
| POST | `/register` | Register a new user |
| POST | `/login` | Login and generate JWT |
| GET | `/users/me` | Retrieve logged-in user profile |
| GET | `/protected` | Access protected information |
| GET | `/admin/users` | View all registered users (Admin only) |

## Authentication Workflow

1. A new user registers by providing a username, email and password.
2. The password is hashed using bcrypt before being stored in the database.
3. During login, the entered credentials are verified.
4. After successful login, the application generates a JWT access token.
5. The token is used to access protected API endpoints.
6. The application validates the token before providing access to protected resources.

## Role-Based Access Control (RBAC)

The application supports two roles:

**1. Normal User**
- Register and log in.
- View their own profile.
- Access authenticated routes.

**2. Admin**
- Access authenticated routes.
- View the list of registered users.
- Access administrator-specific endpoints.

Normal users are restricted from accessing administrator-only endpoints.

## Expected Authentication Responses

| HTTP Status | Meaning |
|---|---|
| 200 | Request successful |
| 201 | User registered successfully |
| 401 | Unauthorized access |
| 403 | Insufficient permissions |
| 409 | Username or email already exists |

## Author

**Shrinivas Naik**

B.E. Computer Science and Engineering

Anjuman Institute of Technology and Management, Bhatkal

GitHub: https://github.com/shrinivasnaik27

---

Developed as part of a Python FastAPI backend development task.