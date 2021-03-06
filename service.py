import random
import re
import string
from datetime import datetime

import requests
from bson.objectid import ObjectId
from twilio.rest import TwilioRestClient
import creds

def random_yo_handle():
    r = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for _ in range(8))
    return 'YM'+r

# Create service model.
class Service():
    """
    Fields
    - _id
    - code
    - yo_handle
    - yo_api_key
    - need_extra
    - fields
    - name
    - dscrpt
    - tags
    - public
    - need_loc
    - rating
    - owner
    - ts
    """
    def __init__(self, json):
        self._id = json['_id'] if '_id' in json else None
        self.code = json['code'] if 'code' in json else None
        self.yo_handle = json['yo_handle'] if 'yo_handle' in json else None
        self.yo_api_key = json['yo_api_key'] if 'yo_api_key' in json else None
        self.need_extra = json['need_extra'] if 'need_extra' in json else None
        self.fields = json['fields'] if ('fields' in json and self.need_extra) else None
        self.name = json['name'] if 'name' in json else None
        self.dscrpt = json['dscrpt'] if 'dscrpt' in json else None
        self.tags = json['tags'] if 'tags' in json else None
        self.rating = json['rating'] if 'rating' in json else 0
        self.owner = json['owner'] if 'owner' in json else None
        self.ts = json['ts'] if 'ts' in json else datetime.now()

    def _to_dict(self, include_id=True):
        d = {}
        if self._id is not None and not include_id:
            d['_id'] = self._id
        if self.code is not None:
            d['code'] = self.code
        if self.yo_handle is not None:
            d['yo_handle'] = self.yo_handle
        if self.yo_api_key is not None:
            d['yo_api_key'] = self.yo_api_key
        if self.need_extra is not None:
            d['need_extra'] = self.need_extra
        if self.fields is not None:
            d['fields'] = self.fields
        if self.name is not None:
            d['name'] = self.name
        if self.dscrpt is not None:
            d['dscrpt'] = self.dscrpt
        if self.tags is not None:
            d['tags'] = self.tags
        if self.rating is not None:
            d['rating'] = self.rating
        if self.owner is not None:
            d['owner'] = self.owner
        if self.ts is not None:
            d['ts'] = self.ts
        return d

    def __repr__(self):
        return self.name

    def _make_yo_handle(self, db):
        while True:
            handle = random_yo_handle()
            print "trying handle:", handle
            r = requests.post(
                'https://api.justyo.co/accounts/',
                data={
                    'new_account_username': handle,
                    'new_account_passcode': creds.universal_password,
                    'callback_url': 'http://yomote.co/yoback/' + str(self._id),
                    'api_token': creds.yo_api_key
                })
            if r.ok:
                self.yo_handle = r.json()['username']
                self.yo_api_key = r.json()['api_token']
                return True
            else:
                print r.content
        return True

    def save(self, db):
        print 'saving'
        if self._id is not None:
            if db.services.find({'_id': self._id}).count() > 0:
                db.services.update({'_id': self._id},
                                   {'$set': self._to_dict(False)})
                return True
            return False
        self._id = db.services.insert(self._to_dict())
        self._make_yo_handle(db)
        self.save(db)
        return True

    def run(self, db, req):
        def subscribers_count():
            print 'counting'
            r = requests.get(
                'https://api.justyo.co/subscribers_count/',
                params={'api_token': self.yo_api_key})
            if r.okay:
                return r.json()['result']

        def yoall(link=None):
            print 'yoing all'
            params = {'api_token': self.yo_api_key}
            if link is not None:
                params['link'] = link
            r = requests.post(
                'https://api.justyo.co/yoall/',
                params=params)
            print r.ok, r.text
            return r.ok

        def yo(username, link=None, location=None):
            print 'yoing %s' % username
            data = {'username': username.upper(), 'api_token': self.yo_api_key}
            if link is not None:
                data['link'] = link
            if location is not None and link is None:
                data['location'] = location
            r = requests.post(
                'https://api.justyo.co/yo/',
                data=data)
            print r.ok, r.text
            return r.ok

        globals_ = {'requests': requests, 're': re, 'now': datetime.now,
                    'TwilioRestClient': TwilioRestClient}
        locals_ = {
            'subscribers_count': subscribers_count,
            'yoall': yoall,
            'yo': yo,
            'username': req['username']}
        if 'location' in req:
            locals_['location'] = req['location']
        if 'link' in req:
            locals_['link'] = req['link']
        if self.need_extra:
            cursor = db.users.find({'yo_handle': req['username']})
            if cursor.count() == 0:
                return
            u = cursor.next()
            cursor = db.user_data.find({'user': u['_id'], 'service': self._id})
            print {'user': u['_id'], 'service': self._id}
            if cursor.count() == 0:
                return
            locals_['user_data'] = cursor.next()['data']
        try:
            exec self.code in globals_, locals_
        except Exception, e:
            print e
