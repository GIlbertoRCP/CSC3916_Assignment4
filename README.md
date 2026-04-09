# CSC3916 Assignment 4 - Web API with Reviews and Analytics

## Explanation of the Project
This project is a RESTful Web API built with Node.js, Express, and MongoDB. It expands upon previous assignment by introducing a `Reviews` collection that is relationally tied to a `Movies` collection. Users can sign up and sign in using JWT authentication. Authenticated users can create movies, fetch movies, and post reviews for specific movies. The API uses MongoDB to join movies and their associated reviews when the query parameter is provided. The assignment also implements the server-side Google Analytics tracking to monitor how many times specific movies are reviewed.

**Live Deployed Render side:** https://csc3916-react19-hwk4.onrender.com/

## Installation and Usage Instructions
### Prerequisites
* Node.js installed locally
* A MongoDB cluster (Atlas or local)
* A Google Analytics Measurement ID

### Running Locally
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/GIlbertoRCP/CSC3916_Assignment4.git


[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 128px; height: 32px;">](https://app.getpostman.com/run-collection/51781414-78c8381d-7671-4aae-8ee1-8eaad4da181f?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D51781414-78c8381d-7671-4aae-8ee1-8eaad4da181f%26entityType%3Dcollection%26workspaceId%3Dad503f4d-c90d-463b-a9c4-2d00855cb098)