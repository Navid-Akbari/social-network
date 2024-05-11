This is a personal beginner project that I started in order to try and understand the underlying implementations that could exist in a social network app's backend.
The APIs are restful and all the requests rely on JWT token authentication using JWT library.
Users can create accounts, upload a profile picture, create posts and like them or comment on them. They can send friend requests and cancel their request or have 
it accepted or rejected by the targeted user. all these features have been designed with rest_framework library, django's ORM and serializers.
The application also allows users to have one-on-one chatting using django_channels to establish websockets. All users' interactions and chat history is saved to the 
database and retrieved after one of them enters the chat again.
