# StoryShare Backend API

This is the backend API for StoryShare, developed by ORAE IBC. StoryShare is a platform for sharing stories and images with friends. This API provides the necessary functionality for user accounts, friend management, and image sharing within the StoryShare application.

## Installation and Setup

To set up and run this backend API for StoryShare, follow these steps:

1. **Clone the Repository:**

2. **Install Dependencies:**

3. **Database Configuration:**

   - Create a SQLite database file named `db.sqlite` in the `./storage/` directory. You can use a SQLite client to create this database.

4. **Run the Application:**

   ```shell
   python index.py
   ```

   The API will start running on `http://localhost:5000`.

## Usage

Once the StoryShare Backend API is up and running, you can interact with it using HTTP requests. Below, you'll find a list of available API endpoints and their descriptions.

## User Account Management

### Register User

- **Endpoint:** `/account/register`
- **Method:** `POST`
- **Description:** Register a new user account.
- **Request Body:** JSON containing `user`, `mail`, and `pasw` (password).
- **Response:** User registration status and a token on success.

### User Login

- **Endpoint:** `/account/login`
- **Method:** `POST`
- **Description:** Log in an existing user.
- **Request Body:** JSON containing `mail` and `pasw` (password).
- **Response:** User login status and a token on success.

### Get User Information

- **Endpoint:** `/account/me`
- **Method:** `POST`
- **Description:** Get information about the currently authenticated user.
- **Request Headers:** `auth` (token).
- **Response:** User information.

### Delete User Account

- **Endpoint:** `/account/delete`
- **Method:** `POST`
- **Description:** Delete the user's account.
- **Request Body:** JSON containing `pasw` (password).
- **Request Headers:** `auth` (token).
- **Response:** Account deletion status.

## Friendship Management

### Add Friend

- **Endpoint:** `/friends/add`
- **Method:** `POST`
- **Description:** Send a friend request to another user.
- **Request Body:** JSON containing `friend` (username of the friend to add).
- **Request Headers:** `auth` (token).
- **Response:** Friend request status.

### Accept Friend Request

- **Endpoint:** `/friends/accept`
- **Method:** `POST`
- **Description:** Accept a pending friend request.
- **Request Body:** JSON containing `friend` (username of the friend to accept).
- **Request Headers:** `auth` (token).
- **Response:** Friend request acceptance status.

### Reject Friend Request

- **Endpoint:** `/friends/reject`
- **Method:** `POST`
- **Description:** Reject a pending friend request.
- **Request Body:** JSON containing `friend` (username of the friend to reject).
- **Request Headers:** `auth` (token).
- **Response:** Friend request rejection status.

### Remove Friend

- **Endpoint:** `/friend/remove`
- **Method:** `POST`
- **Description:** Remove a friend from the user's friend list.
- **Request Body:** JSON containing `friend` (username of the friend to remove).
- **Request Headers:** `auth` (token).
- **Response:** Friend removal status.

### Get Friend Information

- **Endpoint:** `/friends/info`
- **Method:** `POST`
- **Description:** Get information about a friend, including their name and status.
- **Request Body:** JSON containing `FriendID` (the ID of the friend to get information about).
- **Request Headers:** `auth` (token).
- **Response:** Friend information, including name and status.

### List Friends

- **Endpoint:** `/friends/list`
- **Method:** `GET`
- **Description:** Get a list of all friends and friend requests for the authenticated user.
- **Request Headers:** `auth` (token).
- **Response:** List of friends and friend requests.

## Image Sharing

### Upload Image

- **Endpoint:** `/cam/new`
- **Method:** `POST`
- **Description:** Upload a new image.
- **Request Body:** JSON containing `img` (image data).
- **Request Headers:** `auth` (token).
- **Response:** Image upload status.

### View Image

- **Endpoint:** `/home/<friend>/<image>`
- **Method:** `GET`
- **Description:** View a specific image associated with a friend.
- **Request Headers:** `auth` (token).
- **Response:** The requested image file or a "Not Found" message if the image does not exist.

## License

This code is licensed under the ORAE License. For more details, please visit [ORAE License](https://orae.one/license).