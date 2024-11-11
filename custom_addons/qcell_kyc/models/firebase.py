import firebase_admin
from firebase_admin import credentials, messaging

firebase_cred = credentials.Certificate('firebase.json')
firebase_app = firebase_admin.initialize_app(firebase_cred)

"""


def subscribe_news(tokens):  # tokens is a list of registration tokens
    topic = 'news'
    response = messaging.subscribe_to_topic(tokens, topic)
    if response.failure_count > 0:
        print(f'Failed to subscribe to topic {topic} due to {list(map(lambda e: e.reason, response.errors))}')


def unsubscribe_news(tokens):  # tokens is a list of registration tokens
    topic = 'news'
    response = messaging.unsubscribe_from_topic(tokens, topic)
    if response.failure_count > 0:
        print(f'Failed to subscribe to topic {topic} due to {list(map(lambda e: e.reason, response.errors))}')


def send_topic_push(title, body):
    topic = 'news'
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body
        ),
        topic=topic
    )
    messaging.send(message)


def send_token_push(title, body, tokens):
    message = messaging.MulticastMessage(
        notification=messaging.Notification(
            title=title,
            body=body
        ),
        tokens=tokens
    )
    messaging.send_multicast(message)

from firebase_admin import messaging
"""


def send_to_token():
    # [START send_to_token]
    # This registration token comes from the client FCM SDKs.
    registration_token = 'cBxYVozrRJapHzJpQ5kl45:APA91bH8_Eu2uWFp0f9HEYYh0Fx4-zmbZCA02SmTF69B5ophV_G53DrnnrMxiM0jZlqIKusm5PcdnrAaZWfH2PefQvK_tVRVXbObif6heBp2p6vUjqzs5L1WbtajUtRKR_hDChjCU6Qz'

    # See documentation on defining a message payload.
    message = messaging.Message(
        data={
            'title': 'Hello Alfred',
            'body': 'Reminder to approve payroll for general staff',
            'route': 'payroll'
        },
        token=registration_token,
    )

    # Send a message to the device corresponding to the provided
    # registration token.
    response = messaging.send(message)
    # Response is a message ID string.
    print('Successfully sent message:', response)
    # [END send_to_token]


send_to_token()
