from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests
import constants

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
from urllib.parse import quote_plus


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

# 👆 We're continuing from the steps above. Append this to your server.py file.

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get('APP_SECRET_KEY')

client = datastore.Client()

PAGE_SIZE = 5

# Update the values of the following 3 variables
CLIENT_ID = '01puV5DOtaAwCHhafGNuzd2wEXvIqfun'
CLIENT_SECRET = 'zsRYDdS5NVYs_2NgL96EfbTGUvootoV6OEnpsw-6ehmLkhOYGd3jVLhKCgJ4PZQc'
DOMAIN = 'dev-h6ni4kmpsmgdmhko.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

auth1 = oauth.register(
    'auth1',
    client_id='72Q7UKP11UmK1DK4w1UPfiELw2LYZvke',
    client_secret='2d5se0BW4WnVzUAfoJMaBUOdsgO9RLJCpkPoCsy8NXzjUniAhlPcR-wdvsClg7hz',
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

#------------------------------------------------------------------------------------

@app.route('/users', methods=['GET'])
def get_users():
    #payload = oauth.auth1.authorize_access_token()
    #header = {'authorization': "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNNTlpLbU1aMGZkNmhOajV1QjFuZyJ9.eyJpc3MiOiJodHRwczovL2Rldi1oNm5pNGttcHNtZ2RtaGtvLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiI3MlE3VUtQMTFVbUsxREs0dzFVUGZpRUx3MkxZWnZrZUBjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9kZXYtaDZuaTRrbXBzbWdkbWhrby51cy5hdXRoMC5jb20vYXBpL3YyLyIsImlhdCI6MTcwMTkwNTI5MSwiZXhwIjoxNzAxOTkxNjkxLCJhenAiOiI3MlE3VUtQMTFVbUsxREs0dzFVUGZpRUx3MkxZWnZrZSIsInNjb3BlIjoicmVhZDpjbGllbnRfZ3JhbnRzIGNyZWF0ZTpjbGllbnRfZ3JhbnRzIGRlbGV0ZTpjbGllbnRfZ3JhbnRzIHVwZGF0ZTpjbGllbnRfZ3JhbnRzIHJlYWQ6dXNlcnMgdXBkYXRlOnVzZXJzIGRlbGV0ZTp1c2VycyBjcmVhdGU6dXNlcnMgcmVhZDp1c2Vyc19hcHBfbWV0YWRhdGEgdXBkYXRlOnVzZXJzX2FwcF9tZXRhZGF0YSBkZWxldGU6dXNlcnNfYXBwX21ldGFkYXRhIGNyZWF0ZTp1c2Vyc19hcHBfbWV0YWRhdGEgcmVhZDp1c2VyX2N1c3RvbV9ibG9ja3MgY3JlYXRlOnVzZXJfY3VzdG9tX2Jsb2NrcyBkZWxldGU6dXNlcl9jdXN0b21fYmxvY2tzIGNyZWF0ZTp1c2VyX3RpY2tldHMgcmVhZDpjbGllbnRzIHVwZGF0ZTpjbGllbnRzIGRlbGV0ZTpjbGllbnRzIGNyZWF0ZTpjbGllbnRzIHJlYWQ6Y2xpZW50X2tleXMgdXBkYXRlOmNsaWVudF9rZXlzIGRlbGV0ZTpjbGllbnRfa2V5cyBjcmVhdGU6Y2xpZW50X2tleXMgcmVhZDpjb25uZWN0aW9ucyB1cGRhdGU6Y29ubmVjdGlvbnMgZGVsZXRlOmNvbm5lY3Rpb25zIGNyZWF0ZTpjb25uZWN0aW9ucyByZWFkOnJlc291cmNlX3NlcnZlcnMgdXBkYXRlOnJlc291cmNlX3NlcnZlcnMgZGVsZXRlOnJlc291cmNlX3NlcnZlcnMgY3JlYXRlOnJlc291cmNlX3NlcnZlcnMgcmVhZDpkZXZpY2VfY3JlZGVudGlhbHMgdXBkYXRlOmRldmljZV9jcmVkZW50aWFscyBkZWxldGU6ZGV2aWNlX2NyZWRlbnRpYWxzIGNyZWF0ZTpkZXZpY2VfY3JlZGVudGlhbHMgcmVhZDpydWxlcyB1cGRhdGU6cnVsZXMgZGVsZXRlOnJ1bGVzIGNyZWF0ZTpydWxlcyByZWFkOnJ1bGVzX2NvbmZpZ3MgdXBkYXRlOnJ1bGVzX2NvbmZpZ3MgZGVsZXRlOnJ1bGVzX2NvbmZpZ3MgcmVhZDpob29rcyB1cGRhdGU6aG9va3MgZGVsZXRlOmhvb2tzIGNyZWF0ZTpob29rcyByZWFkOmFjdGlvbnMgdXBkYXRlOmFjdGlvbnMgZGVsZXRlOmFjdGlvbnMgY3JlYXRlOmFjdGlvbnMgcmVhZDplbWFpbF9wcm92aWRlciB1cGRhdGU6ZW1haWxfcHJvdmlkZXIgZGVsZXRlOmVtYWlsX3Byb3ZpZGVyIGNyZWF0ZTplbWFpbF9wcm92aWRlciBibGFja2xpc3Q6dG9rZW5zIHJlYWQ6c3RhdHMgcmVhZDppbnNpZ2h0cyByZWFkOnRlbmFudF9zZXR0aW5ncyB1cGRhdGU6dGVuYW50X3NldHRpbmdzIHJlYWQ6bG9ncyByZWFkOmxvZ3NfdXNlcnMgcmVhZDpzaGllbGRzIGNyZWF0ZTpzaGllbGRzIHVwZGF0ZTpzaGllbGRzIGRlbGV0ZTpzaGllbGRzIHJlYWQ6YW5vbWFseV9ibG9ja3MgZGVsZXRlOmFub21hbHlfYmxvY2tzIHVwZGF0ZTp0cmlnZ2VycyByZWFkOnRyaWdnZXJzIHJlYWQ6Z3JhbnRzIGRlbGV0ZTpncmFudHMgcmVhZDpndWFyZGlhbl9mYWN0b3JzIHVwZGF0ZTpndWFyZGlhbl9mYWN0b3JzIHJlYWQ6Z3VhcmRpYW5fZW5yb2xsbWVudHMgZGVsZXRlOmd1YXJkaWFuX2Vucm9sbG1lbnRzIGNyZWF0ZTpndWFyZGlhbl9lbnJvbGxtZW50X3RpY2tldHMgcmVhZDp1c2VyX2lkcF90b2tlbnMgY3JlYXRlOnBhc3N3b3Jkc19jaGVja2luZ19qb2IgZGVsZXRlOnBhc3N3b3Jkc19jaGVja2luZ19qb2IgcmVhZDpjdXN0b21fZG9tYWlucyBkZWxldGU6Y3VzdG9tX2RvbWFpbnMgY3JlYXRlOmN1c3RvbV9kb21haW5zIHVwZGF0ZTpjdXN0b21fZG9tYWlucyByZWFkOmVtYWlsX3RlbXBsYXRlcyBjcmVhdGU6ZW1haWxfdGVtcGxhdGVzIHVwZGF0ZTplbWFpbF90ZW1wbGF0ZXMgcmVhZDptZmFfcG9saWNpZXMgdXBkYXRlOm1mYV9wb2xpY2llcyByZWFkOnJvbGVzIGNyZWF0ZTpyb2xlcyBkZWxldGU6cm9sZXMgdXBkYXRlOnJvbGVzIHJlYWQ6cHJvbXB0cyB1cGRhdGU6cHJvbXB0cyByZWFkOmJyYW5kaW5nIHVwZGF0ZTpicmFuZGluZyBkZWxldGU6YnJhbmRpbmcgcmVhZDpsb2dfc3RyZWFtcyBjcmVhdGU6bG9nX3N0cmVhbXMgZGVsZXRlOmxvZ19zdHJlYW1zIHVwZGF0ZTpsb2dfc3RyZWFtcyBjcmVhdGU6c2lnbmluZ19rZXlzIHJlYWQ6c2lnbmluZ19rZXlzIHVwZGF0ZTpzaWduaW5nX2tleXMgcmVhZDpsaW1pdHMgdXBkYXRlOmxpbWl0cyBjcmVhdGU6cm9sZV9tZW1iZXJzIHJlYWQ6cm9sZV9tZW1iZXJzIGRlbGV0ZTpyb2xlX21lbWJlcnMgcmVhZDplbnRpdGxlbWVudHMgcmVhZDphdHRhY2tfcHJvdGVjdGlvbiB1cGRhdGU6YXR0YWNrX3Byb3RlY3Rpb24gcmVhZDpvcmdhbml6YXRpb25zX3N1bW1hcnkgY3JlYXRlOmF1dGhlbnRpY2F0aW9uX21ldGhvZHMgcmVhZDphdXRoZW50aWNhdGlvbl9tZXRob2RzIHVwZGF0ZTphdXRoZW50aWNhdGlvbl9tZXRob2RzIGRlbGV0ZTphdXRoZW50aWNhdGlvbl9tZXRob2RzIHJlYWQ6b3JnYW5pemF0aW9ucyB1cGRhdGU6b3JnYW5pemF0aW9ucyBjcmVhdGU6b3JnYW5pemF0aW9ucyBkZWxldGU6b3JnYW5pemF0aW9ucyBjcmVhdGU6b3JnYW5pemF0aW9uX21lbWJlcnMgcmVhZDpvcmdhbml6YXRpb25fbWVtYmVycyBkZWxldGU6b3JnYW5pemF0aW9uX21lbWJlcnMgY3JlYXRlOm9yZ2FuaXphdGlvbl9jb25uZWN0aW9ucyByZWFkOm9yZ2FuaXphdGlvbl9jb25uZWN0aW9ucyB1cGRhdGU6b3JnYW5pemF0aW9uX2Nvbm5lY3Rpb25zIGRlbGV0ZTpvcmdhbml6YXRpb25fY29ubmVjdGlvbnMgY3JlYXRlOm9yZ2FuaXphdGlvbl9tZW1iZXJfcm9sZXMgcmVhZDpvcmdhbml6YXRpb25fbWVtYmVyX3JvbGVzIGRlbGV0ZTpvcmdhbml6YXRpb25fbWVtYmVyX3JvbGVzIGNyZWF0ZTpvcmdhbml6YXRpb25faW52aXRhdGlvbnMgcmVhZDpvcmdhbml6YXRpb25faW52aXRhdGlvbnMgZGVsZXRlOm9yZ2FuaXphdGlvbl9pbnZpdGF0aW9ucyByZWFkOnNjaW1fY29uZmlnIGNyZWF0ZTpzY2ltX2NvbmZpZyB1cGRhdGU6c2NpbV9jb25maWcgZGVsZXRlOnNjaW1fY29uZmlnIGNyZWF0ZTpzY2ltX3Rva2VuIHJlYWQ6c2NpbV90b2tlbiBkZWxldGU6c2NpbV90b2tlbiBkZWxldGU6cGhvbmVfcHJvdmlkZXJzIGNyZWF0ZTpwaG9uZV9wcm92aWRlcnMgcmVhZDpwaG9uZV9wcm92aWRlcnMgdXBkYXRlOnBob25lX3Byb3ZpZGVycyBkZWxldGU6cGhvbmVfdGVtcGxhdGVzIGNyZWF0ZTpwaG9uZV90ZW1wbGF0ZXMgcmVhZDpwaG9uZV90ZW1wbGF0ZXMgdXBkYXRlOnBob25lX3RlbXBsYXRlcyBjcmVhdGU6ZW5jcnlwdGlvbl9rZXlzIHJlYWQ6ZW5jcnlwdGlvbl9rZXlzIHVwZGF0ZTplbmNyeXB0aW9uX2tleXMgZGVsZXRlOmVuY3J5cHRpb25fa2V5cyIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9.ZwqvRe1V0rgBT5B8WqK6IiqBlzKHexnPwXgXnf5S3Qzl_eXiYhCNNKa6soQn8NeqnLaYEwE-GOPxRG5KGVJXhf0aybdGe4NiLMjnBy-_JrddpZw4nIqIlLp1EtdTtvHl55IGhFWUTdKaPvIH-k3UYA8gbW5lDRU0WZHJ1PTb_xc4YfItMXB4WKYHV6V3OtskejxHtOE7lU_i_4aKV_bZ4vwprUBb_4h6aqjh2bDvPsGxNldnXn3HhpPlozvX3vdx8P2LGi2M5GOXHjgvLIlozucuaJnxjIuPCAW5AP692MUXhnJMxhHTRAgekh2SJSKQu2wzPbCaUqhbCLQ7ASU8NQ",
    #           'content-type': "application/json"}
    #user_url = 'https://' + DOMAIN + '/api/v2/users'
    #response = requests.get(user_url, headers=header)
    #return response.text, 200, {'content-type':"application/json"}
    query = client.query(kind=constants.users)
    query_iter = query.fetch()
    results = list(query_iter)
    users = []
    for user in results:
        user_data = {
            "unique ID": user["unique ID"]
        }
        users.append(user_data)
    return jsonify(users), 200


# Create a lodging if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST'])
def boats_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()

        if request.headers['Accept'] != 'application/json':
            return jsonify({"Error": "Not Acceptable"}), 406

        if "name" not in content or "type" not in content or "length" not in content:
            error_message = "The request object is missing at least one of the required attributes"
            return json.dumps({"Error": error_message}), 400
        
        content["loads"] = []

        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"], "public": content["public"], "owner": payload["sub"]})
        client.put(new_boat)

        boat_id = new_boat.key.id

        self_url = f"{request.url_root}/boats/{boat_id}"

        new_boat.update({"self": self_url})
        client.put(new_boat)

        response_data = {
        "id": new_boat.key.id,
        "name": new_boat["name"],
        "type": new_boat["type"],
        "length": new_boat["length"],
        "public": new_boat["public"],
        "loads": [],
        "owner": new_boat["owner"],
        "self": self_url
    }
        return jsonify(response_data), 201
    else:
        return jsonify(error='Method not recogonized')

@app.route('/owners/<string:owner_id>/boats', methods=['GET'])
def get_owner_boats(owner_id):
    # Query Datastore to retrieve public boats for the specified owner_id
    query = client.query(kind=constants.boats)
    query.add_filter("owner", "=", owner_id)
    query.add_filter("public", "=", "true")
    results = list(query.fetch())

    if request.headers['Accept'] != 'application/json':
        return json.dumps({"Error": "Not Acceptable"}), 406

    # Format boat data
    boats_data = []
    for boat in results:
        boat_data = {
            "id": boat.key.id,
            "name": boat["name"],
            "type": boat["type"],
            "length": boat["length"],
            "public": boat["public"],
            "loads": boat.get("loads", []),
            "owner": boat["owner"],
            "self": boat["self_url"]
        }
        boats_data.append(boat_data)

    # Return the boat data as a JSON response
    return jsonify(boats_data), 200

@app.route('/boats/<int:boat_id>', methods=['GET'])
def view_boat(boat_id):
    try:
        # Check if a JWT is provided in the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split()
            token = auth_header[1]

            # Attempt to verify the JWT and extract the owner (sub) from the payload
            payload = verify_jwt(request)
            owner_id = payload.get("sub")

            # Query Datastore to retrieve the boat by boat_id
            boat_key = client.key(constants.boats, boat_id)
            boat = client.get(boat_key)

            if request.headers['Accept'] != 'application/json':
                return json.dumps({"Error": "Not Acceptable"}), 406

            if boat:
                boat_owner = boat["owner"]

                # Check if the boat owner matches the owner in the JWT
                if boat_owner == owner_id:
                    boat["id"] = boat.key.id
                    return jsonify(boat), 200
                else:
                    # Return a 403 status code if the boat is owned by someone else
                    return jsonify(error="Forbidden"), 403
            else:
                # Return a 403 status code if no boat with the given boat_id exists
                return jsonify(error="No boat with this boat_id exists"), 404

        else:
            # Return a 401 status code for missing or invalid JWTs
            return jsonify(error="Unauthorized"), 401

    except AuthError as e:
        # Handle JWT verification errors and return a 401 status code
        print("JWT Verification Error:", e)
        return jsonify(error="Unauthorized"), 401
    except Exception as e:
        # Handle other exceptions and return a 500 status code
        print("Exception:", e)
        return jsonify(error="Internal Server Error"), 500

# Modify the existing /boats route for GET requests
@app.route('/boats', methods=['GET'])
def get_boats():
    cursor = request.args.get('cursor', None)
    # Check if a JWT is provided in the Authorization header
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]

        if request.headers['Accept'] != 'application/json':
            return json.dumps({"Error": "Not Acceptable"}), 406

        try:
            # Attempt to verify the JWT and extract the owner (sub) from the payload
            payload = verify_jwt(request)
            owner_id = str(payload.get("sub"))

            # Query Datastore to retrieve boats based on the owner or all public boats
            query = client.query(kind=constants.boats)
            if owner_id:
                # If a valid owner_id is extracted from the JWT, filter by owner
                query.add_filter("owner", "=", owner_id)
            else:
                # If no valid owner_id is found, filter by public boats only
                query.add_filter("public", "=", "true")
            query_iter = query.fetch(limit=PAGE_SIZE, start_cursor=cursor)
            results = list(query_iter)

            if query_iter.next_page_token:
                next_cursor = query_iter.next_page_token.decode('utf-8')
                next_url = f"{request.base_url}?cursor={next_cursor}"
            else:
                next_url = None

            # Format boat data for the owner
            boats_data = []
            for boat in results:
                boat_data = {
                    "id": str(boat.key.id),
                    "name": boat["name"],
                    "type": boat["type"],
                    "length": boat["length"],
                    "public": boat["public"],
                    "loads": boat.get("loads", []),
                    "owner": boat["owner"],
                    "self": boat["self"]
                }
                boats_data.append(boat_data)

            output = {"boats": boats_data}
            if next_url:
                output["next"] = next_url

            # Return the boat data for the owner as a JSON response with a 200 status code
            return jsonify(output), 200

        except AuthError as e:
            # Handle JWT verification errors, but continue to retrieve public boats
            print("JWT Verification Error:", e)
            return jsonify(error="Forbidden"), 403
    

    # If no valid JWT is provided, or JWT verification fails, return all public boats
    """
    query = client.query(kind=constants.boats)
    query.add_filter("public", "=", "true")
    query_iter = query.fetch(limit=PAGE_SIZE, start_cursor=cursor)
    results = list(query_iter)

    if query_iter.next_page_token:
        next_cursor = query_iter.next_page_token.decode('utf-8')
        next_url = f"{request.base_url}?cursor={next_cursor}"
    else:
        next_url = None

    # Format boat data for all public boats
    boats_data = []
    for boat in results:
        boat_data = {
            "id": str(boat.key.id),
            "name": boat["name"],
            "type": boat["type"],
            "length": boat["length"],
            "public": boat["public"],
            "loads": boat.get("loads", [])
        }
        boats_data.append(boat_data)

    output = {"boats": boats_data}
    if next_url:
        output["next"] = next_url

    # Return the boat data for all public boats as a JSON response with a 200 status code
    return jsonify(output), 200
    """

@app.route('/boats', methods=['PUT', 'DELETE'])
def boats_not_allowed():
    return json.dumps({"Error": "Method Not Allowed"}), 405

@app.route('/boats/<int:boat_id>', methods=['DELETE'])
def delete_boat(boat_id):
    try:
        # Check if a JWT is provided in the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split()
            token = auth_header[1]

            # Attempt to verify the JWT and extract the owner (sub) from the payload
            payload = verify_jwt(request)
            owner_id = payload.get("sub")

            # Query Datastore to retrieve the boat by boat_id
            boat_key = client.key(constants.boats, boat_id)
            boat = client.get(boat_key)

            if boat:
                boat_owner = boat["owner"]

                # Check if the boat owner matches the owner in the JWT
                if boat_owner == owner_id:
                    # Delete the boat and return a 204 status code
                    for load in boat.get('loads', []):
                        load_key = client.key(constants.loads, load['id'])
                        associated_load = client.get(load_key)
                        if associated_load:
                            associated_load["carrier_id"] = None
                            associated_load["carrier"] = None
                            client.put(associated_load)

                    client.delete(boat_key)
                    return '', 204
                else:
                    # Return a 403 status code if the boat is owned by someone else
                    return jsonify(error="Forbidden"), 403
            else:
                # Return a 403 status code if no boat with the given boat_id exists
                return jsonify(error="Forbidden"), 404

        else:
            # Return a 401 status code for missing or invalid JWTs
            return jsonify(error="Unauthorized"), 401

    except AuthError as e:
        # Handle JWT verification errors and return a 401 status code
        print("JWT Verification Error:", e)
        return jsonify(error="Unauthorized"), 401
    except Exception as e:
        # Handle other exceptions and return a 500 status code
        print("Exception:", e)
        return jsonify(error="Internal Server Error"), 500
    
@app.route('/boats/<int:boat_id>', methods=['PATCH'])
def patch_boat(boat_id):
    try:
        # Check if a JWT is provided in the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split()
            token = auth_header[1]

            # Attempt to verify the JWT and extract the owner (sub) from the payload
            payload = verify_jwt(request)
            owner_id = payload.get("sub")

            # Query Datastore to retrieve the boat by boat_id
            boat_key = client.key(constants.boats, boat_id)
            boat = client.get(boat_key)

            if request.headers['Content-Type'] != 'application/json':
                return json.dumps({"Error": "Unsupported Media Type"}), 415
    
            if request.headers['Accept'] != 'application/json':
                return json.dumps({"Error": "Not Acceptable"}), 406

            if boat:
                boat_owner = boat["owner"]

                # Check if the boat owner matches the owner in the JWT
                if boat_owner == owner_id:
                    # Delete the boat and return a 204 status code
                    data = request.get_json()

                    for field in data:
                        if field not in ['id', 'self']:  
                            boat[field] = data[field]

                    client.put(boat)
                    
                    return jsonify(boat), 204
                else:
                    # Return a 403 status code if the boat is owned by someone else
                    return jsonify(error="Forbidden"), 403
            else:
                # Return a 403 status code if no boat with the given boat_id exists
                return jsonify(error="Forbidden"), 404

        else:
            # Return a 401 status code for missing or invalid JWTs
            return jsonify(error="Unauthorized"), 401

    except AuthError as e:
        # Handle JWT verification errors and return a 401 status code
        print("JWT Verification Error:", e)
        return jsonify(error="Unauthorized"), 401
    except Exception as e:
        # Handle other exceptions and return a 500 status code
        print("Exception:", e)
        return jsonify(error="Internal Server Error"), 500
    
@app.route('/boats/<int:boat_id>', methods=['PUT'])
def put_boat(boat_id):
    try:
        # Check if a JWT is provided in the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split()
            token = auth_header[1]

            # Attempt to verify the JWT and extract the owner (sub) from the payload
            payload = verify_jwt(request)
            owner_id = payload.get("sub")

            # Query Datastore to retrieve the boat by boat_id
            boat_key = client.key(constants.boats, boat_id)
            boat = client.get(boat_key)

            if request.headers['Content-Type'] != 'application/json':
                return json.dumps({"Error": "Unsupported Media Type"}), 415
    
            if request.headers['Accept'] != 'application/json':
                return json.dumps({"Error": "Not Acceptable"}), 406

            if boat:
                boat_owner = boat["owner"]

                # Check if the boat owner matches the owner in the JWT
                if boat_owner == owner_id:
                    # Delete the boat and return a 204 status code
                    data = request.get_json()

                    if not all(field in data for field in ['name', 'type', 'length']):
                        error_message = "The request object is missing at least one of the required attributes"
                        return json.dumps({"Error": error_message}), 400

                    boat.update({
                        'name': data['name'],
                        'type': data['type'],
                        'length': data['length'],
                        'public': data['public']
                    })

                    client.put(boat)
                    
                    return jsonify(boat), 204
                else:
                    # Return a 403 status code if the boat is owned by someone else
                    return jsonify(error="Forbidden"), 403
            else:
                # Return a 403 status code if no boat with the given boat_id exists
                return jsonify(error="Forbidden"), 404

        else:
            # Return a 401 status code for missing or invalid JWTs
            return jsonify(error="Unauthorized"), 401

    except AuthError as e:
        # Handle JWT verification errors and return a 401 status code
        print("JWT Verification Error:", e)
        return jsonify(error="Unauthorized"), 401
    except Exception as e:
        # Handle other exceptions and return a 500 status code
        print("Exception:", e)
        return jsonify(error="Internal Server Error"), 500
    
@app.route('/loads', methods=['POST'])
def create_load():
    data = request.get_json()

    if request.headers['Accept'] != 'application/json':
        return json.dumps({"Error": "Not Acceptable"}), 406

    if "volume" not in data or "item" not in data or "creation_date" not in data:
            error_message = "The request object is missing at least one of the required attributes"
            return json.dumps({"Error": error_message}), 400
    
    data["carrier"] = None

    with client.transaction():
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update(data)
        client.put(new_load)

    load_id = new_load.key.id

    self_url = f"{request.url_root}loads/{load_id}"

    new_load.update({"self": self_url})
    client.put(new_load)
    

    response_data = {
        "id": new_load.key.id,
        "volume": data["volume"],
        "item": data["item"],
        "creation_date": data["creation_date"],
        "carrier": None,
        "self": self_url
    }

    return jsonify(response_data), 201

@app.route('/loads', methods=['GET'])
def get_loads():
    cursor = request.args.get('cursor', None)

    query = client.query(kind=constants.loads)
    query_iter = query.fetch(limit=PAGE_SIZE, start_cursor=cursor)
    results = list(query_iter)

    if request.headers['Accept'] != 'application/json':
        return json.dumps({"Error": "Not Acceptable"}), 406

    if query_iter.next_page_token:
        next_cursor = query_iter.next_page_token.decode('utf-8')
        next_url = f"{request.base_url}?cursor={next_cursor}"
    else:
        next_url = None

    loads = []
    for load in results:
        load_data = {
            "id": load.key.id,
            "volume": load["volume"],
            "item": load["item"],
            "creation_date": load["creation_date"],
            "carrier": load.get("carrier", None),
            "self": load["self"]
        }
        loads.append(load_data)

    output = {"loads": loads}
    if next_url:
        output["next"] = next_url

    return jsonify(output), 200

@app.route('/loads/<int:load_id>', methods=['GET'])
def view_load(load_id):
    load_key = client.key(constants.loads, load_id)
    load = client.get(load_key)

    if request.headers['Accept'] != 'application/json':
        return json.dumps({"Error": "Not Acceptable"}), 406

    if not load:
        return json.dumps({"Error": "No load with this load_id exists"}), 404

    load["id"] = load.key.id
    return jsonify(load), 200

@app.route('/loads/<int:load_id>', methods=['DELETE'])
def delete_load(load_id):
    load_key = client.key(constants.loads, load_id)
    load = client.get(load_key)
    
    if not load:
        return json.dumps({"Error": "No load with this load_id exists"}), 404

    if load.get('carrier_id'):
        boat_key = client.key(constants.boats, load['carrier_id'])
        associated_boat = client.get(boat_key)
        if associated_boat and 'loads' in associated_boat:
            associated_boat['loads'] = [l for l in associated_boat.get('loads', []) if l['id'] != load_id]
            client.put(associated_boat)

    client.delete(load_key)
    
    return '', 204

@app.route('/loads/<int:load_id>', methods=['PATCH'])
def update_boat_partial(load_id):
    load_key = client.key(constants.loads, load_id)
    load = client.get(load_key)

    if request.headers['Content-Type'] != 'application/json':
        return json.dumps({"Error": "Unsupported Media Type"}), 415
    
    if request.headers['Accept'] != 'application/json':
        return json.dumps({"Error": "Not Acceptable"}), 406

    if not load:
        return json.dumps({"Error": "No load with this load_id exists"}), 404

    data = request.get_json()

    for field in data:
        if field not in ['id', 'self']:  
            load[field] = data[field]

    client.put(load)
    
    return jsonify(load), 204

@app.route('/boats/<int:boat_id>/loads/<int:load_id>', methods=['PUT'])
def update_load_carrier(boat_id, load_id):

    boat_key = client.key(constants.boats, boat_id)
    boat = client.get(boat_key)

    load_key = client.key(constants.loads, load_id)
    load = client.get(load_key)

    if request.headers['Accept'] != 'application/json':
        return json.dumps({"Error": "Not Acceptable"}), 406

    if not boat or not load:
        return json.dumps({"Error": "The specified boat and/or load does not exist"}), 404

    if load["carrier"] is not None:
            return json.dumps({"Error": "The load is already loaded on another boat"}), 403

    load.update({"carrier_id": boat_id})
    load["carrier"] = {
        "id": boat_id,
        "name": boat["name"],
        "self": f"{request.url_root}boats/{boat_id}"
    }
    client.put(load)

    load_entry = {
        "id": load_id,
        "self": f"{request.url_root}loads/{load_id}",
        "item": load.get("item", ""),
        "creation_date": load.get("creation_date", ""),
        "volume": load.get("volume", 0)
    }
    boat_loads = boat.get("loads", [])
    boat_loads.append(load_entry)
    boat["loads"] = boat_loads
    client.put(boat)

    return '', 204

@app.route('/boats/<int:boat_id>/loads/<int:load_id>', methods=['DELETE'])
def delete_load_from_boat(boat_id, load_id):
    boat_key = client.key(constants.boats, boat_id)
    boat = client.get(boat_key)

    if not boat:
        return json.dumps({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404

    load_key = client.key(constants.loads, load_id)
    load = client.get(load_key)

    if not load:
        return json.dumps({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404

    if load["carrier_id"] != boat_id:
        return json.dumps({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404

    load_entry = {
        "id": load_id,
        "self": f"{request.url_root}loads/{load_id}",
        "item": load.get("item", ""),
        "creation_date": load.get("creation_date", ""),
        "volume": load.get("volume", 0)
    }

    if load_entry in boat.get("loads", []):
        boat["loads"].remove(load_entry)
        client.put(boat)

    load["carrier_id"] = None
    load["carrier"] = None
    client.put(load)

    return '', 204
    
#-------------------------------------------------------------------------------------

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

# 👆 We're continuing from the steps above. Append this to your server.py file.

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

# 👆 We're continuing from the steps above. Append this to your server.py file.

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

# 👆 We're continuing from the steps above. Append this to your server.py file.

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

# 👆 We're continuing from the steps above. Append this to your server.py file.

@app.route("/")
def home():
    new_user = datastore.entity.Entity(key=client.key(constants.users))
    new_user.update({"unique ID": session.get('user')})
    client.put(new_user)
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

