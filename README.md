# Password Manager Backend

A secure backend server for the Password Manager application built with Node.js, Express, and MongoDB.

## Features

- User authentication with JWT
- Password encryption and secure storage
- RESTful API endpoints
- MongoDB integration
- CORS enabled
- Environment variables support

## API Endpoints

### Authentication
- `POST /signup` - Create a new user account
- `POST /login` - User login

### Password Management (Protected Routes)
- `GET /passwords` - Get all passwords for authenticated user
- `POST /passwords` - Add new password
- `PUT /passwords/:id` - Update password
- `DELETE /passwords/:id` - Delete password

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file with the following variables:
```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
PORT=3000
```

3. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## Security Features

- Password hashing using bcrypt
- JWT-based authentication
- Protected routes
- User-specific password access
- Environment variables for sensitive data
