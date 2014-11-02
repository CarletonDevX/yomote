from bson.objectid import ObjectId
from flask import Flask, url_for, redirect, render_template, request, abort
from flask.ext import admin, login
from flask.ext.admin import helpers, expose
from service import Service
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import form, fields, validators
import pymongo
import requests

# Create Flask application
app = Flask(__name__, static_folder='static')
db = pymongo.MongoClient().yomote

# Create dummy secrey key so we can use sessions
app.config['SECRET_KEY'] = 'asdfyoloswag'

# the YoAPI

class Yo:
    def __init__(self, token):
        self.token = token

    def number(self):
        """
        Function to GET the the number of subscribers of the API user account.
        Returns number of subscribers as an integer.
        If request is unsuccessful, raises an error.
        """
        number_url = "http://api.justyo.co/subscribers_count/?api_token=" + self.token
        number = requests.get(number_url)
        if number.status_code == requests.codes.ok:
            return number.json()["result"]
        else:
            number.raise_for_status()

    def yoall(self, *link):
        """
        Function to send a Yo to all subscribers of the API user account.
        If request is successful, returns true.
        If request is unsuccessful, raises an error.
        """
        yoall_data = {"api_token": self.token, "link": link}
        yoall_url = "http://api.justyo.co/yoall/"
        yoall = requests.post(yoall_url, data=yoall_data)
        if yoall.status_code == requests.codes.created:
               return True
        else:
               yoall.raise_for_status()

    def youser(self, username, *link):
        """
        Function to send a Yo to a specific username.
        If request is successful, returns true.
        If request is unsuccessful, raises an error.
        """
        username = username.upper()
        youser_data = {"api_token": self.token, "username": username, "link": link}
        youser_url = "http://api.justyo.co/yo/"
        youser = requests.post(youser_url, data=youser_data)
        if youser.status_code == requests.codes.ok:
            return True
        else:
            yoall.raise_for_status()

# Create user model.
class User():
    """
    Fields
    - _id
    - yo_handle
    - password
    """
    def __init__(self, json):
        if json is None:
            self._none = True
        else:
            self._none = False
            self._id = str(json['_id'])
            self.yo_handle = json['yo_handle'].upper()
            self.password = json['password']

    def is_authenticated(self):
        return not self._none

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self._id if not self._none else None

    # Required for administrative interface
    def __unicode__(self):
        return self.yo_handle if not self._none else ''


# Define the User password reset token database
class ResetPassword():
    """
    Fields
    - _id
    - yo_handle
    """
    def __init__(self, json):
        if json is None:
            self._none = True
        else:
            self._none = False
            self._id = str(json['_id'])
            self.yo_handle = json['yo_handle']

# Define login and registration forms (for flask-login)
class LoginForm(form.Form):
    yo_handle = fields.TextField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_yo_handle(self, field):
        user = self.get_user()

        if user._none:
            raise validators.ValidationError('Invalid user')

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
        # to compare plain text passwords use
        # if user.password != self.password.data:
            raise validators.ValidationError('Invalid password')

    def get_user(self):
        cursor = db.users.find({'yo_handle': self.yo_handle.data.upper()})
        if cursor.count() > 0:
            return User(cursor.next())
        else:
            return User(None)


class RegistrationForm(form.Form):
    yo_handle = fields.TextField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_yo_handle(self, field):
        yh = self.yo_handle.data.upper()
        if db.users.find({'yo_handle': yh}).count() > 0:
            raise validators.ValidationError('Duplicate username')


class ResetForm(form.Form):
    yo_handle = fields.HiddenField('',[validators.Required(),])
    newpassword = fields.PasswordField(
        'New Password', [validators.Required(),])
    confirmpassword = fields.PasswordField(
        'Confirm New Password',
        [validators.Required(),
         validators.EqualTo('newpassword',message='Password Must Match')])

class ForgetPasswordForm(form.Form):
    yo_handle=fields.TextField('Yo Handle',[validators.Required(),])


# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        cursor = db.users.find({'_id': ObjectId(user_id)})
        if cursor.count() > 0:
            return User(cursor.next())
        else:
            return User(None)


# Create customized index view class that handles login & registration
class MyAdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated():
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        # handle user login
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            login.login_user(user)

        if login.current_user.is_authenticated():
            return redirect(url_for('.index'))
        link = "<p>Don\'t have an account? <a href='" + \
               url_for('.register_view') + \
               "'>Click here to register.</a></p>" + \
                "<p>Forget your password? <a href='" + \
               url_for('.get_token') + \
               "'>Reset Here.</a></p>"
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = {
                'yo_handle': form.yo_handle.data.upper(),
                'password': generate_password_hash(form.password.data)
            }
            user['_id'] = db.users.insert(user)
            user = User(user)

            login.login_user(user)
            return redirect(url_for('.index'))
        link = "<p>Already have an account? <a href='" + \
               url_for('.login_view') + \
               ">Click here to log in.</a></p>"
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/forgetpassword/',methods=('GET','POST'))
    def get_token(self):
       form=ForgetPasswordForm(request.values)
       if helpers.validate_form_on_submit(form):
         yosend=Yo(token='235e961d-a1f3-429b-9f57-290a99fa8712')
         uid=str(db.resettoken.insert({"yo_handle":str(form.yo_handle.data)}))
         yosend.youser(str(form.yo_handle.data),"http://yomote.co/"+uid)
         return 'Check your Yo to reset password!'
       return render_template("reset.html", form=form)

    @expose('/logout/')
    def logout_view(self):
        login.logout_user()
        return redirect(url_for('.index'))


# Flask views
@app.route('/')
def index():
    services = map(Service,
        db.services.find({'yo_handle': {'$exists': 1}}).limit(100))
    return render_template('index.html', services=services,
        c=('#' if login.current_user.is_authenticated() else '/admin'))


@app.route('/recent')
def recent_yos():
    services = map(Service,
        db.services.find(
            {'yo_handle': {'$exists': 1}}
        ).sort('ts', pymongo.DESCENDING).limit(100))
    return render_template('services.html', services=services)


@app.route('/hot')
def hot_yos():
    services = map(Service,
        db.services.find(
            {'yo_handle': {'$exists': 1}}
        ).sort('rating', pymongo.DESCENDING).limit(100))
    return render_template('services.html', services=services)


@app.route('/search')
def search_yos():
    search_terms = request.args['search'].strip().split()
    services = map(Service,
        db.services.find(
            {'$or':[
                {'tags': {'$in': search_terms}},
                {'dscrpt': {'$regex': '|'.join(search_terms)}},
                {'name': {'$regex': '|'.join(search_terms)}}
            ], 'yo_handle': {'$exists': 1}}
        ).sort('rating', pymongo.DESCENDING).limit(100))
    return render_template('services.html', services=services)


@app.route('/create', methods=('GET',))
def new_service_render():
    if not login.current_user.is_authenticated():
        return redirect(url_for('admin.login_view'))
    return render_template('create_service.html')


@app.route('/create', methods=('POST',))
def new_service_make():
    if not login.current_user.is_authenticated():
        return redirect(url_for('admin.login_view'))    
    data = {x: request.values.getlist(x) for x in list(request.values)}
    data = {x: data[x][0]
            if (len(data[x]) == 1 and x not in ['tags', 'fields'])
            else data[x]
            for x in data}
    data['owner'] = ObjectId(login.current_user._id)
    s = Service(data)
    print s._to_dict()
    s.save(db)
    print s._to_dict()    
    return redirect('/finish/' + str(s._id))


@app.route('/finish/<service_id>', methods=('GET',))
def finish_service_render(service_id):
    if not login.current_user.is_authenticated():
        return redirect(url_for('admin.login_view'))
    oid = None
    try:
        oid = ObjectId(service_id)
    except Exception, e:
        return redirect('/sry/poorly%20formed%20url')
    cursor = db.services.find({'_id': oid})
    if cursor.count() == 0:
        return redirect('/sry/no%20such%20service%20exists')
    s = Service(cursor.next())
    if str(s.owner) != login.current_user._id:
        return render_template('sry.html',
            text='but this doesn\'t belong to you')
    return render_template('finish_service.html',
        s_id=str(s._id), s_name=s.name,
        callback="http://yomote.co/yoback/" + str(s._id))


@app.route('/finish/<service_id>', methods=('POST',))
def finish_service_make(service_id):
    if not login.current_user.is_authenticated():
        return redirect(url_for('admin.login_view'))
    oid = None
    try:
        oid = ObjectId(service_id)
    except Exception, e:
        return redirect('/sry/poorly%20formed%20url')
    cursor = db.services.find({'_id': oid})
    if cursor.count() == 0:
        return redirect('/sry/no%20such%20service%20exists')
    s = Service(cursor.next())
    if str(s.owner) != login.current_user._id:
        return render_template('sry.html',
            text='but this doesn\'t belong to you')
    s.yo_handle = request.form['yo_handle'].upper().strip()
    s.yo_api_key = request.form['yo_api_key'].strip()
    s.save(db)
    return redirect('/')


@app.route('/sry/<text>')
def sry(text):
    return render_template('sry.html', text=text)


@app.route('/add/<service_id>', methods=('GET',))
def add_yo(service_id):
    oid = None
    try:
        oid = ObjectId(service_id)
    except Exception, e:
        return redirect('/sry/poorly%20formed%20url')
    cursor = db.services.find({'_id': oid, 'yo_handle': {'$exists': 1}})
    if cursor.count() == 0:
        return redirect('/sry/no%20such%20service%20exists')
    s = Service(cursor.next())
    if s.need_extra:
        return render_template('add_params.html', s_id=s._id, fields=s.fields)
    else:
        return redirect('http://www.justyo.co/%s/' % s.yo_handle)

@app.route('/add/<service_id>', methods=('POST',))
def add_yo2(service_id):
    if not login.current_user.is_authenticated():
        return redirect(url_for('admin.login_view'))
    oid = None
    try:
        oid = ObjectId(service_id)
    except Exception, e:
        return redirect('/sry/poorly%20formed%20url')
    cursor = db.services.find({'_id': oid, 'yo_handle': {'$exists': 1}})
    if cursor.count() == 0:
        return redirect('/sry/no%20such%20service%20exists')
    s = Service(cursor.next())
    if s.need_extra:
        data = {x: request.form[x] for x in request.form if x in s.fields}
        if len(data.keys()) != len(s.fields):
            return render_template('add_params.html', s_id=s._id, fields=s.fields)
        db.user_data.update({'user': ObjectId(login.current_user._id),
                             'service': s._id},
                            {'$set': {'data': data}}, upsert=True)
        return redirect('http://www.justyo.co/%s/' % s.yo_handle)
    else:
        return redirect('http://www.justyo.co/%s/' % s.yo_handle)


@app.route('/yoback/<service_id>')
def yoback(service_id, methods=('POST',)):
    print 'got yo'
    oid = None
    try:
        oid = ObjectId(service_id)
    except Exception, e:
        return abort(404)
    cursor = db.services.find({'_id': oid})
    if cursor.count() == 0:
        return abort(404)
    s = Service(cursor.next())
    data = {x: request.args[x] for x in request.args
            if x in ['username', 'link', 'location']}
    s.run(db, data)
    db.services.update({'_id': s._id}, {'$inc': {'rating': 1}})
    return 'yo'


#look up the token and direct to reset form
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    cursor = db.resettoken.find({'_id': ObjectId(token)})
    count=cursor.count()
    if count==1:
            usrn=cursor.next()['yo_handle']
    else: return str(count)
    form=ResetForm(request.values,yo_handle=usrn)
    if request.method == 'POST' and form.validate():
        handle=form.data['yo_handle']
        psw=form.data['newpassword']
        db.users.update({"yo_handle" : handle},{'$set':{ "password":generate_password_hash(psw)
}})
        return redirect('/')
    return render_template("reset.html", form=form)

# Initialize flask-login
init_login()


# Create admin
admin = admin.Admin(app, 'Accounts', index_view=MyAdminIndexView(),
    base_template='my_master.html')


if __name__ == '__main__':
    # Start app
    app.run(debug=True)
