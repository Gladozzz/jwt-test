# jwt-test
## server
31.172.77.224:8000
## api
- **/** - need JWT Token.
- **/register** - form: {"login": "<login>", "password": "<password>"}
- **/login** - form: {"login": "<login>","password": "<password>"}
- **/token/refresh** - form: {"refresh_token": "<refresh_token>"}
- **/logout** - form: {"access_token": "<access_token>"}
- **/token/deleteall** - form: {"login": "<login>", "password": "<password>"}
