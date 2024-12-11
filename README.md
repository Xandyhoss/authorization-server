# Authorization Server

The **Authorization Server** is a flexible and secure service designed to handle authentication and authorization for any application. This server leverages JWT tokens and PostgreSQL for robust user management.

---

## Features

- User authentication with JWT tokens.
- User metadata storage for application-specific information.
- Secure token refreshing and user logout functionalities.

---

## Requirements

- Docker
- Node.js 20

---

## Getting Started

Run the following command to start both the PostgreSQL and the Dockerized application containers:  
`./start.sh`  

---

## API Endpoints

### User Management

- **`GET /users`**  
  List all users on the server.

- **`POST /user/login`**  
  Logs in a user.  
  **Parameters:**  
  - `login`: The user's login.  
  - `password`: The user's password.

- **`GET /user/logout`**  
  Logs out a user.

- **`POST /user/create`**  
  Creates a new user.  
  **Parameters:**  
  - `login`: The desired login for the user.  
  - `password`: The user's password.  
  - `user_metadata`: A JSON object containing application-specific data about the user.

- **`DELETE /user/delete/:id`**  
  Deletes a user based on the provided `id`.

### Authentication

- **`GET /authenticate`**  
  Authenticates a user based on their `access_token`.

- **`GET /refresh`**  
  Refreshes an expired `access_token` and updates the `refresh_token` if it is still valid.

---

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue to suggest improvements or report bugs.

---

## License

This project is licensed under the [MIT License](LICENSE).
