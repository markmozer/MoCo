from msal import ConfidentialClientApplication
import requests
from config import Config

GRAPH_ENDPOINT = 'https://graph.microsoft.com/v1.0/me/sendMail'


def get_access_token():
    authority = f'https://login.microsoftonline.com/{Config.MSAL_TENANT_ID}'
    scopes = ['https://graph.microsoft.com/.default']
    msal_app = ConfidentialClientApplication(
        Config.MSAL_CLIENT_ID,
        authority=authority,
        client_credential=Config.MSAL_CLIENT_SECRET
    )
    token_response = msal_app.acquire_token_for_client(scopes=scopes)
    access_token = token_response['access_token']

    if not access_token:
        print("Failed to acquire token")
        return None
    else:
        print("Token acquired for graph API")
        return access_token


class MSGraphAPI():
    def __init__(self):
        self.access_token = get_access_token()

    def send_email(self, subject, body, recipient):
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Replace the following email details
        email_data = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": body
                },
                "toRecipients": [
                    {"emailAddress": {"address": recipient}}
                ]
            }
        }

        response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{Config.UPN}/sendMail',
            headers=headers,
            json=email_data
        )

        print(response.status_code, response.reason)
