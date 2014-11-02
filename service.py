import random

import requests

import creds

def random_yo_handle():
    r = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for _ in range(8))
    return 'Y4-'+r

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
    - public
    """
    def __init__(self, json):
        self._id = str(json['_id']) if '_id' in json else None
        self.code = json['code'] if 'code' in json else None
        self.yo_handle = json['yo_handle'] if 'yo_handle' in json else None
        self.yo_api_key = json['yo_api_key'] if 'yo_api_key' in json else None
        self.need_extra = json['need_extra'] if 'need_extra' in json else None
        self.fields = json['fields'] if 'fields' in json else None
        self.name = json['name'] if 'name' in json else None
        self.dscrpt = json['dscrpt'] if 'dscrpt' in json else None
        self.public = json['public'] if 'public' in json else None
        self.need_loc = json['need_loc'] if 'need_loc' in json else None

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
        if self.public is not None:
            d['public'] = self.public
        if self.need_loc is not None:
            d['need_loc'] = self.need_loc
        return d

    def __repr__(self):
        return self.name

    def _make_yo_handle(self, db):
        if self._id is None:
            return False
        while True:
            handle = random_yo_handle()
            r = requests.post(
                'https://api.justyo.co/accounts/',
                data={
                    'new_account_username': handle,
                    'new_account_passcode': creds.universal_password,
                    'callback_url': 'http://yomote.co/yoback/' + self._id
                    'needs_location': self.needs_location,
                    'api_token': creds.yo_api_key
                })
            if r.ok:
                self.yo_handle = handle
        return True

    def save(self, db):
        if self._id:
            if db.services.find({'_id': self.id}).count() > 0:
                db.services.update({'_id': self.id},
                                   {'$set': self._to_dict(False)})
                return True
            return False
        self._id = str(db.services.insert(self._to_dict()))
        return True

    def run(self, db, req):
        def subscribers_count():
            r = requests.get(
                'https://api.justyo.co/subscribers_count/',
                params={'api_token': self.yo_api_key})
            if r.okay:
                return r.json()['result']

        def yoall(link=None):
            params = {'api_token': self.yo_api_key}
            if link is not None:
                params['link'] = link
            r = requests.post(
                'https://api.justyo.co/yoall/',
                params=params)
            return r.ok

        def yo(self, username, link=None, location=None):
            data = {'username': username.upper(), 'api_token': self.yo_api_key}
            if link is not None:
                data['link'] = link
            if location is not None and link is None:
                data['location'] = location
            r = requests.post(
                'https://api.justyo.co/yo/',
                data=data)
            return r.ok

        pass
