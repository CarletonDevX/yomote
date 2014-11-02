from flask import Flask, url_for, redirect, render_template, request
from flask.ext import admin, login
from flask.ext.admin import helpers, expose
import pymongo
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import form, fields, validators
import requests
from bson.objectid import ObjectId

# Create Flask application
app = Flask(__name__, static_folder='static')
db = pymongo.MongoClient().yofor

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
            self.yo_handle = json['yo_handle']
            self.password = json['password']

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self._id if not self._none else None

    # Required for administrative interface
    def __unicode__(self):
        return self.yo_handle if not self._none else ''


# Create service model.
class Service():
    """
    Fields
    - _id
    - code
    - yo_handle
    - need_extra
    - fields
    - name
    - dscrpt
    - public
    """
    def __init__(self, json):
        self._id = json['_id'] if '_id' in json else None
        self.code = json['code'] if 'code' in json else None
        self.yo_handle = json['yo_handle'] if 'yo_handle' in json else None
        self.need_extra = json['need_extra'] if 'need_extra' in json else None
        self.fields = json['fields'] if 'fields' in json else None
        self.name = json['name'] if 'name' in json else None
        self.dscrpt = json['dscrpt'] if 'dscrpt' in json else None
        self.public = json['public'] if 'public' in json else None

    def __repr__(self):
        return self.name
#Define  the User password reset token database
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

# D login and registration forms (for flask-login)
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
        cursor = db.users.find({'yo_handle': self.yo_handle.data})
        if cursor.count() > 0:
            return User(cursor.next())
        else:
            return User(None)


class RegistrationForm(form.Form):
    yo_handle = fields.TextField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_yo_handle(self, field):
        if db.users.find({'yo_handle': self.yo_handle.data}).count() > 0:
            raise validators.ValidationError('Duplicate username')


class ResetForm(form.Form):
    yo_handle = fields.HiddenField('',[validators.Required(),])
    newpassword = fields.PasswordField('New Password', [validators.Required(),])
    confirmpassword=fields.PasswordField('Confirm New Password',[validators.Required(),validators.EqualTo('newpassword',message='Password Must Match'),
])

class ForgetPasswordForm(form.Form):
    yo_handle=fields.TextField('Yo Handle',[validators.Required(),])
# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        cursor = db.users.find({'_id': user_id})
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
                'yo_handle': form.yo_handle.data,
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
    services = map(Service, db.services.find({'public': True}))
    return render_template('index.html', services=services)

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
admin = admin.Admin(app, 'Example: Auth', index_view=MyAdminIndexView(),
    base_template='my_master.html')


if __name__ == '__main__':
    # Start app
    app.run(debug=True)
