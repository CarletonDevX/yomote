import creds
from twilio.rest import TwilioRestClient
import requests
# Find these values at https://twilio.com/user/account
account_sid = creds.API_TWILIO_SID
auth_token = creds.API_TWILIO_TOKEN
client = TwilioRestClient(account_sid, auth_token)
print str(message = client.messages.create(to="+15073211499", from_="+15075818278",
body="Hello there!"))

##implement using requests
#r=requests.post('https://api.twilio.com/2010-04-01/'+account_sid+'/'+auth_token+'/'+'{"From":"+15075818278","To":"+15073211499","Body":"hey"}')
