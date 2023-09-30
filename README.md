# StoryShare Backend

Welcome to the StoryShare backend repository. In this README, you will find the latest updates on API endpoints and domain information for StoryShare.

## Todo
### /friends/list
- **Description:** List all your friends.
- **Requires:** [Authentication](#authentication)

## Domains

StoryShare Backend is accessible at the following domain: [https://api.storyshare.orae.one/](https://api.storyshare.orae.one/)

## API Endpoints

### /home
- **Description:** Connects the user to the homepage.
- **Requires:** [Authentication](#authentication)

### /home/(friend)/(image)
- **Description:** Connect to a sent image.
- **Requires:** [Authentication](#authentication)

### /account/register
- **Description:** Register a new account.
- **Body Parameters:** [username, mail, pasw]

### /account/login
- **Description:** Authenticate the user.
- **Body Parameters:** [mail, pasw]

### /account/delete
- **Description:** Delete the account.
- **Requires:** [Authentication](#authentication)
- **Body Parameters:** [pasw]

### /cam/new
- **Description:** Create a new story.
- **Requires:** [Authentication](#authentication)
- **Body Parameters:** [[img](#encoding)]

### /friend/add
- **Description:** Add a friend.
- **Requires:** [Authentication](#authentication)
- **Body Parameters:** [friend]

### /friend/accept
- **Description:** Accept a active friend request
- **Requires:** [Authenication](#authentication)
- **Body Parameters:** [friend]

### /friend/remove
- **Description:** Remove a active friendship
- **Requires:** [Authenication](#authentication)
- **Body Parameters:** [friend]

## Authentication

To access the API, you need an API Token, which you can acquire by following these steps:
1. Initiate an API request to [/register](#accountregister), or use [/login](#accountlogin).
2. You will receive a response with a parameter: token=(sessionToken).
3. Use this token in the authorization header of your requests to access the unlocked endpoints.

## Encryption

We are committed to implementing end-to-end encryption for our app. Once you have authenticated, the sessionToken will automatically serve as the encryption token for your communications.

## Encoding

We encode our images using Base64 when sending a POST request to the server. For example, when uploading a photo in the [/new](#camnew) request, include the [img] parameter in the request body with the base64-encoded image.


## Questions?

Do you want to know more about the backend api? You can create a [Issue] on this repo.

Thank you!