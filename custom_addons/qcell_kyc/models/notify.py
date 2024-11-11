# Send to single device.
from pyfcm import FCMNotification

push_service = FCMNotification(api_key="AIzaSyA6pthfrCx1wGedpTHIqTPWUliKOcaBQmc")
"""

# OR initialize with proxies

proxy_dict = {
          "http"  : "http://127.0.0.1",
          "https" : "http://127.0.0.1",
        }
push_service = FCMNotification(api_key="L3FU8P2N3N", proxy_dict=proxy_dict)
"""

# Your api-key can be gotten from:  https://console.firebase.google.com/project/<project-name>/settings/cloudmessaging

registration_id = "f14vOZg8S9CDVJncjT5o7Y:APA91bFQR0Two31l5-m4GFh4rFk4pPkkL5dc5AVRNrwCPyCu2mn17_c86WbmV8ym04YkO7kWp4mxsU7vAllQ-3F9LnJkv-MQAc-Hkve0rSF6rwD5xLd5KbkHOw4D0dlvwzJGu0nUO9M3"
message_title = "Byte ERP"
message_body = "Test for Byte ERP"
result = push_service.notify_single_device(registration_id=registration_id, message_title=message_title, message_body=message_body)

"""
# Send to multiple devices by passing a list of ids.
registration_ids = ["<device registration_id 1>", "<device registration_id 2>", ...]
message_title = "Uber update"
message_body = "Hope you're having fun this weekend, don't forget to check today's news"
result = push_service.notify_multiple_devices(registration_ids=registration_ids, message_title=message_title, message_body=message_body)
"""

print (result)