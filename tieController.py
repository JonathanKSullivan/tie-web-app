import datetime, random, string, json, requests, httplib2, os
from flask import Flask, render_template, make_response, request, redirect, jsonify, url_for, flash, send_from_directory
from flask import session as login_session
from flask_mail import Mail, Message
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Event, Correspondence, Ticket, Testimonial, Blog, Log
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from werkzeug import secure_filename
from decorators import async
import braintree
#from OpenSSL import SSL
from flask_jsglue import JSGlue
import barcode
from barcode.writer import ImageWriter
from itsdangerous import URLSafeTimedSerializer


#from flask.ext.httpauth import HTTPBasicAuth
#auth = HTTPBasicAuth()


app = Flask(__name__)
jsglue = JSGlue(app)
mail=Mail(app)
app.config.update(
    DEBUG=True,
    #EMAIL SETTINGS
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = 'jonathan.k.sullivan@gmail.com',
    MAIL_PASSWORD = 'kirkpatrick'
    )
mail=Mail(app)

braintree.Configuration.configure(braintree.Environment.Sandbox,
                                  merchant_id="dckt3zc3bpqgzgkj",
                                  public_key="jnz8wxgsdjcfrbwm",
                                  private_key="122df64983f8d2bbabc407380521dcaa")

engine = create_engine('sqlite:///tiewebapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

linkedin_client_id = "'78cqxw06026ji9'"
linkedin_client_secret = "'X8Kb9Wf3CEyZ1h3k'"
authorization_base_url = 'https://www.linkedin.com/uas/oauth2/authorization'
token_url = 'https://www.linkedin.com/uas/oauth2/accessToken'
gtracker = ''
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "TIE Training Application"
ADMINISTRATION_PROFILES = [1,2] 
UPLOAD_FOLDER = './static/images/uploads/'
ALLOWED_EXTENSIONS = set(['svg', 'apng', 'bmp', 'png', 'jpg', 'jpeg', 'gif'])
MAIL_DEFAULT_SENDER="jonathan.k.sullivan@gmail.com"

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    print 'a1'
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    print 'a2'
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        print 'a3'
    except:
        return False
        print 'a4'
    print 'a5'
    return True

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def createUser(login_session, password):
    newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'], password=password)
    session.add(newUser)
    session.commit()
    activity = "User created"
    newLog = Log(timestamp= datetime.datetime.today(), user_id= session.query(User).filter_by(email=login_session['email']).one().id, activity=activity)
    session.add(newLog)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    send_async_email(app, msg)

def send_ticket(text_body, html_body, msg):
    msg.body = text_body
    msg.html = html_body
    send_async_email(app, msg)

def check_user_existance(user_id=None, password=''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))):
    user_id = getUserID(login_session['email'])
    print user_id
    if not user_id:
        user_id = createUser(login_session, password)
    login_session['user_id'] = user_id
def configure_login_output():
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    return output

def bad_state():
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

def set_session_data(provider, data):
    print data
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['ADMINISTRATION_PROFILES'] = ADMINISTRATION_PROFILES
    if provider == 'facebook':
        login_session['provider'] = 'facebook'
        login_session['facebook_id'] = data["id"]
    elif provider == 'google':
        login_session['provider'] = 'google'
    elif provider == 'linkedin':
        login_session['picture'] = data['image']
        login_session['provider'] = 'linkedin'
    elif provider == 'live':
        login_session['picture'] = data['image']
        login_session['provider'] = 'live'


def set_facebook_picture(token):
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

def set_google_picture(data):
    login_session['picture'] = data['picture']

def get_session_data(provider, token):
    if provider == 'facebook':
        url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        return json.loads(result)
    if provider == 'google':
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        return answer.json()

def get_oauth_result(provider, access_token):
    if provider == 'facebook':
        app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
        app_secret = json.loads(
            open('fb_client_secrets.json', 'r').read())['web']['app_secret']
        url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
            app_id, app_secret, access_token)
        h = httplib2.Http()
        return h.request(url, 'GET')[1]
    if provider == 'google':
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'% access_token)
        h = httplib2.Http()
        return json.loads(h.request(url, 'GET')[1])

def clear_session_object():
    del login_session['state']
    del login_session['access_token'] 
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    if login_session['provider']=='facebook':
        del login_session['facebook_id']
        del login_session['provider']
    elif login_session['provider']=='google':
        del login_session['gplus_id']
        del login_session['provider']
    elif login_session['provider']=='linkedin': 
        del login_session['provider']
    elif login_session['provider']=='live': 
        del login_session['provider']
        return render_template('mlogout.html')
    elif login_session['provider']=='TIE': 
        del login_session['provider']
    del login_session['ADMINISTRATION_PROFILES']
    flash('Successfully disconnected.')
    return redirect(url_for('main_page'))
@async
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

@app.route("/json/users/")
def api_json_users():
    users = session.query(User).all()
    return jsonify(users = [i.serialize for i in users])

@app.route("/json/events/")
def api_json_events():
    events = session.query(Event).all()
    return jsonify(events = [i.serialize for i in events])

@app.route("/json/ticket/")
def api_json_tickets():
    tickets = session.query(Ticket).all()
    return jsonify(tickets = [i.serialize for i in tickets])

@app.route("/json/testimonial/")
def api_json_testimonials():
    testimonials = session.query(Testimonial).all()
    return jsonify(testimonials = [i.serialize for i in testimonials])

@app.route("/json/correspondence/")
def api_json_correspondences():
    correspondences = session.query(Correspondence).all()
    return jsonify(correspondences = [i.serialize for i in correspondences])

@app.route("/json/blogs/")
def api_json_blogs():
    blogs = session.query(Blog).all()
    return jsonify(blogs = [i.serialize for i in blogs])

@app.route("/json/logs/")
def api_json_logs():
    logs = session.query(Log).all()
    return jsonify(logs = [i.serialize for i in logs])

@app.route("/paypal/<int:quantity>/<int:event_id>/<tracker>", methods=['GET', 'POST'])
def paypal(quantity, event_id, tracker):
    if request.method == 'POST':
        global gtracker
        if tracker != gtracker:
            return bad_state()
        nonce_from_the_client = request.form["payment_method_nonce"]
        result = braintree.Transaction.sale({
            "amount": "10.00",
            "payment_method_nonce": nonce_from_the_client,
            "options": {
              "submit_for_settlement": True
            }
        })
        if result.is_success:
            transaction = result.transaction
            print transaction
            newTicket = Ticket(quantity=quantity, user_id=login_session['user_id'], event_id=event_id, pp_transaction=result.transaction.id)
            session.add(newTicket)
            activity = ''
            activity += str(quantity) + ' tickets bought by ' + login_session['email']
            newLog = Log(timestamp= datetime.datetime.today(), user_id= 0, activity=activity)
            session.add(newLog)
            session.commit()
            ean = barcode.get('code39', result.transaction.id, writer=ImageWriter())
            barcode_filename = ean.save(UPLOAD_FOLDER + result.transaction.id+"_barcode")
            short_filename = result.transaction.id+"_barcode"
            event = session.query(Event).filter_by(id=event_id).one()
            msg = Message("Your Tickets", sender=MAIL_DEFAULT_SENDER, recipients=[login_session['email']])
            print short_filename
            with app.open_resource(barcode_filename[2:]) as fp:
                msg.attach(short_filename+".png", short_filename+"/png", fp.read())
            text = render_template("Ticket.txt",  newTicket=newTicket, event=event, barcode_filename=short_filename)
            html = render_template("Ticket.html", newTicket=newTicket, event=event, barcode_filename=short_filename)
            send_ticket(text_body=text, html_body=html, msg=msg)
        else:
            print [error.code for error in result.errors.all]
        
        flash('Tickets Purchased')
        return redirect(url_for('main_page'))
    else:
        if('username' not in login_session):
            flash('You must login to buy a ticket')
            return redirect(url_for('login'))
        client_token =  braintree.ClientToken.generate()
        event = session.query(Event).filter_by(id=event_id).one()
        resp = make_response(render_template('paypal.html', paypal_client_token = client_token, quantity=quantity, event=event))
        return resp

@app.route('/sw.js')
def manifest():
    res = make_response(render_template('sw.js'), 200)
    res.headers["Content-Type"] = "text/javascript"
    return res

@app.route('/uploads/<filename>/')
def uploaded_file(filename):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

@app.route('/')
def main_page():
    gtracker = ''
    resp = make_response(render_template('main_page.html'))
    return resp

@app.route('/admin/correspondence/<int:message_id>/respond/<isSure>/')
def respond_to_email(message_id, isSure):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    correspondence = session.query(Correspondence).filter_by(id=message_id).one()
    text = render_template("respond_correspondence_email.txt", msg_response= isSure, correspondence= correspondence)
    html = render_template("respond_correspondense_email.html", msg_response= isSure, correspondence= correspondence)
    send_email(subject="Re: Tie Training Correspondence", sender=MAIL_DEFAULT_SENDER, recipients=[correspondence.email], text_body=text, html_body=html)
    resp = make_response(render_template('correspondence_administraion.html'))
    return resp

@app.route('/admin/correspondence/<int:message_id>/forward/<isSure>/')
def forward_email(message_id, isSure):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    correspondence = session.query(Correspondence).filter_by(id=message_id).one()
    text = render_template("forward_correspondence_email.txt", correspondence= correspondence)
    html = render_template("forward_correspondense_email.html", correspondence= correspondence)    
    send_email(subject="FW: TIE Training Correspondence", sender=MAIL_DEFAULT_SENDER, recipients=[isSure], text_body=text, html_body=html)
    resp = make_response(render_template('correspondence_administraion.html'))
    return resp

@app.route('/aboutus/')
def about():
    resp = make_response(render_template('about.html'))
    return resp

@app.route('/services/')
def services():
    resp = make_response(render_template('services.html'))
    return resp

@app.route('/events/')
def events():
    events = session.query(Event).all()
    resp = make_response(render_template('events.html', events = events))
    return resp

@app.route('/refund/<transaction_id>/', methods=['GET'])
def refund(transaction_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    result = braintree.Transaction.refund(transaction_id)
    if result.is_success:
        ticket = session.query(Ticket).filter_by(pp_transaction=transaction_id).one()
        user = session.query(User).filter_by(id=ticket.event_id).one()
        activity = ''
        activity += str(ticket.quantity) + ' tickets refunded to ' + user.email
        newLog = Log(timestamp= datetime.datetime.today(), user_id= session.query(User).filter_by(email=login_session['email']).one().id, activity=activity)
        session.add(newLog)
        session.delete(ticket)
        session.commit()
        #text = render_template("Ticket.txt")
        #html = render_template("Ticket.html")
        #send_email(subject="Your Tickets", sender=MAIL_DEFAULT_SENDER, recipients=[login_session['email']], text_body=text, html_body=html)
    else:
        print [error.code for error in result.errors.all]
    tickets = session.query(Ticket).all()
    users = session.query(User).all()
    events = session.query(Event).all()
    resp = make_response(render_template('ticket_admin.html', users=users, events=events, tickets=tickets))
    return resp

@app.route('/buyTickets/<int:eventid>/', methods=['GET','POST'])
def ticket(eventid):
    if request.method == 'POST':
        quantity = request.form['quantity']
        tracker = request.form['tracker']
        return redirect(url_for('paypal', event_id=eventid, quantity=quantity, tracker=tracker))
    else:
        tracker = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        global gtracker
        gtracker = tracker
        if('username' not in login_session):
            return redirect(url_for('login'))
        event = session.query(Event).filter_by(id=eventid).one()
        resp = make_response(render_template('buy_tickets.html', event = event, tracker=tracker))
        return resp

@app.route('/contact/',  methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        first_name = request.form['name']
        last_name = request.form['surname']
        email = request.form['email']
        country_code = "+1"
        phone = request.form['phone']
        message = request.form['message']
        newCorrespondence = Correspondence(first_name=first_name, last_name=last_name, email=email, country_code=country_code, phone=phone, message=message)
        session.add(newCorrespondence)
        session.commit()
        activity = "Correspondence created"
        newLog = Log(timestamp= datetime.datetime.today(), user_id= 0, activity=activity)
        session.add(newLog)
        session.commit()
        flash('Thanks for reaching out to me, I will contact you shortly. Darylin')
        return redirect(url_for('contact'))
    else:
        resp = make_response(render_template('contact.html'))
        return resp

@app.route('/testimonial/')
def testimonial():
    testimonials = session.query(Testimonial).all()
    users = session.query(User).all()
    resp = make_response(render_template('testimonial.html', testimonials=testimonials, users=users))
    return resp

@app.route('/blog/')
def blog():
    blogs = session.query(Blog).all()
    resp = make_response(render_template('blog.html', blogs=blogs))
    return resp

@app.route('/login/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email= request.form['email']
        password= request.form['password']
        login_session['email']= email
        user_id= getUserID(login_session['email'])
        if not user_id:
            del login_session['email']
            flash('Email Does Not Exist')
            return redirect(url_for('login'))
        user = session.query(User).filter_by(id=user_id).one()
        print(user.verify_password(password))
        if not user.verify_password(password):
            del login_session['email']
            flash('Password is incorrect')
            return redirect(url_for('login'))
        login_session['access_token'] = login_session['state']
        login_session['username'] = user.name
        login_session['provider'] = 'TIE'
        login_session['picture'] = user.picture
        login_session['ADMINISTRATION_PROFILES'] = ADMINISTRATION_PROFILES
        check_user_existance(user_id)

        output = configure_login_output() + \
        ''' 
        <script>
            setTimeout(function() {
              window.location.href = "/";
            }, 4000);
        </script>
        '''
        flash("Now logged in as %s" % login_session['username'])
        return output
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        login_session['state'] = state
        client_ID = "301973621622-ad2c03bpdqe07uci07gn6rbb4bltt1ev.apps.googleusercontent.com"
        #return "The current session state is %s" % login_session['state']
        if('username' in login_session):
        	return redirect(url_for('main_page'))
        resp = make_response(render_template('login.html', STATE=state, client_ID=client_ID))
        return resp

@app.route('/confirm/password/<token>/<email>', methods=['GET', 'POST'])
def confirm(token, email):
    if request.method == 'POST':
        try:
            confirmation = confirm_token(token)
        except:
            flash('The confirmation link is invalid or has expired.', 'danger')
        user = session.query(User).filter_by(email=email).first()
        if not confirmation:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.password_hash = user.hash_password(request.form['password'])
            session.commit()
            flash('You have confirmed your account. Thanks!', 'success')
        return redirect(url_for('main_page'))
    else:
        resp = make_response(render_template('confirm.html'))
        return resp

@app.route('/forgotten/password/', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        print 'aa'
        token = generate_confirmation_token(request.form['email'])
        print 'a'
        token_url = url_for('confirm',token=token, email=request.form['email'], _external=True) 
        print 'b'
        text = render_template("forgotten.txt", token_url=token_url)
        html = render_template("forgotten.html", token_url=token_url)
        print 'c'
        send_email(subject="reset password", sender=MAIL_DEFAULT_SENDER, recipients=[request.form['email']], text_body=text, html_body=html)
        print 'd'
        return redirect(url_for('main_page'))
    else:
        resp = make_response(render_template('reset.html'))
        return resp

@app.route('/login/new/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username=request.form['name']
        email=request.form['email']
        password=request.form['password']
        image=request.files['image']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER_PROFILE'], filename + user_id))
        else:
            filename = 'img/default_profile.png'
        login_session['email'] = email
        user_id = getUserID(login_session['email'])
        if user_id:
            del login_session['email']
            flash('Email Already Exist')
            return redirect(url_for('login'))
        login_session['access_token'] = login_session['state']
        login_session['username'] = username
        login_session['provider'] = 'TIE'
        login_session['picture'] = filename
        login_session['ADMINISTRATION_PROFILES'] = ADMINISTRATION_PROFILES
        check_user_existance(user_id, password)

        output = configure_login_output() + \
        ''' 
        <script>
            setTimeout(function() {
              window.location.href = "/";
            }, 4000);
        </script>
        '''
        flash("Now logged in as %s" % login_session['username'])
        return output

    else:
        if 'username' in login_session:
            return redirect(url_for('main_page'))
        resp = make_response(render_template('signup.html'))
        return resp
@app.route('/mconnect/', methods=['POST'])
def mconnect():

        #return make_response(render_template('login.html'))
    data = {}
    data['name'] = request.json['name']
    data['email'] = request.json['emails']['account']
    data['image'] = 'https://apis.live.net/v5.0/'+request.json['id']+'/picture'
    set_session_data('live', data)
    user_id = getUserID(login_session['email'])
    check_user_existance(user_id)
    output = configure_login_output()
    login_session['access_token'] = login_session['state']
    flash("Now logged in as %s" % login_session['username'])
    return output, 200

@app.route('/lconnect/', methods=['POST'])
def lconnect():
    if request.args.get('state') != login_session['state']:
        return bad_state()
    data = {}
    data['fname'] = request.json['firstName']
    data['lname'] = request.json['lastName']
    data['name'] = data['fname'] + ' ' + data['lname']
    data['email'] = request.json['emailAddress']
    data['image'] = request.json['pictureUrl']
    set_session_data('linkedin', data)
    user_id = getUserID(login_session['email'])
    check_user_existance(user_id)
    output = configure_login_output()
    login_session['access_token'] = login_session['state']
    flash("Now logged in as %s" % login_session['username'])
    return output, 200

@app.route('/fbconnect/', methods=['POST'])
def fbconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        return bad_state()
    # Obtain authorization code
    access_token = request.data
    result = get_oauth_result('facebook', access_token)
    token = result.split("&")[0]
    data = get_session_data('facebook', token)
    set_session_data('facebook', data)
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token
    set_facebook_picture(token)
    user_id = getUserID(login_session['email'])
    check_user_existance(user_id)
    output = configure_login_output()
    flash("Now logged in as %s" % login_session['username'])
    return output

@app.route('/gconnect/', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        return bad_state()
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    result = get_oauth_result('google', access_token)
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    data = get_session_data('google', credentials.access_token)
    set_session_data('google', data)
    set_google_picture(data)
    user_id = getUserID(login_session['email'])
    check_user_existance(user_id)
    output = configure_login_output()
    flash("Now logged in as %s" % login_session['username'])
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect/')
def gdisconnect():
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    return clear_session_object()

@app.route('/fbdisconnect/')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return clear_session_object()

@app.route('/mdisconnect/')
def mdisconnect():
    return clear_session_object()

@app.route('/ldisconnect/')
def ldisconnect():
    return clear_session_object()

@app.route('/tdisconnect/')
def tdisconnect():
    return clear_session_object()

@app.route('/disconnect/')
def disconnect():
    if login_session['provider'] == 'facebook':
        return redirect(url_for('fbdisconnect'))
    elif login_session['provider'] == 'google':
        return redirect(url_for('gdisconnect'))
    elif login_session['provider'] == 'linkedin':
        return redirect(url_for('ldisconnect'))
    elif login_session['provider'] == 'live':
        return redirect(url_for('mdisconnect'))
    elif login_session['provider'] == 'TIE':
        return redirect(url_for('tdisconnect'))

@app.route('/admin/<int:user>/')
def administraion(user):
    if 'user_id' in login_session and login_session['user_id'] in ADMINISTRATION_PROFILES:
        if login_session['user_id'] == user:
            resp = make_response(render_template('admin.html', user=user))
            return resp
    resp = redirect(url_for('main_page'))		
    return resp

@app.route('/admin/events/<int:user>/')
def event_administraion(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    events = session.query(Event).all()
    resp = make_response(render_template('events_admin.html', user=user,  events=events))
    return resp

@app.route('/admin/events/new/<int:user>/',  methods=['GET', 'POST'])
def new_event_administraion(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    if request.method == 'POST':
        size=request.form['size']
        date_in=request.form['date']
        date_processing = date_in.replace('T', '-').replace(':', '-').split('-')
        date_processing = [int(v) for v in date_processing]
        date = datetime.datetime(*date_processing)
        topic=request.form['topic']
        details=request.form['details']
        address=request.form['address']
        city=request.form['city']
        state=request.form['state']
        zipcode=request.form['zipcode']
        cost=request.form['cost']
        user_id = login_session['user_id']
        newEvent = Event(size=size, user_id=user_id, date=date, topic=topic, details=details, address=address, city=city, state=state, zipcode=zipcode, cost=cost)
        session.add(newEvent)
        session.commit()
        activity = "Event on "+ topic +" created"
        newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
        session.add(newLog)
        session.commit()
        flash('Thanks for reaching out to me, I will contact you shortly. Darylin')
        return redirect(url_for('events'))
    else:
        resp = make_response(render_template('new_events_admin.html', user=user))
        return resp

@app.route('/testimonials/new/',  methods=['GET', 'POST'])
def new_testimonials_admin(user=0):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    if request.method == 'POST':
        topic=request.form['topic']
        user_id = login_session['user_id']
        details=request.form['details']
        newTestimonial = Testimonial(headline=topic, content=details, user_id=user_id)
        session.add(newTestimonial)
        session.commit()
        activity = "Testimonial created on " + topic
        newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
        session.add(newLog)
        session.commit()
        flash('Your Testimonial has been added!!')
        return redirect(url_for('testimonial'))
    else:
        resp = make_response(render_template('new_testimonials_admin.html'))
        return resp


@app.route('/admin/blog/new/<int:user>/',  methods=['GET', 'POST'])
def new_blogs_admin(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    if request.method == 'POST':
        image=request.files['image']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        headline=request.form['headline']
        hook=request.form['hook']
        content=request.form['content']
        newBlog = Blog(image=filename, headline=headline, hook=hook, content=content, user_id= login_session['user_id'])
        session.add(newBlog)
        session.commit()
        activity = "Blog created on " + headline
        newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
        session.add(newLog)
        session.commit()
        flash('Your blog has been added!!')
        return redirect(url_for('blog'))
    else:
        resp = make_response(render_template('new_blogs_admin.html', user=user))
        return resp

@app.route('/admin/event/<int:user>/edit/<int:event_id>/',  methods=['GET', 'POST'])
def edit_event_administraion(user, event_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    event_to_edit = session.query(Event).filter_by(id = event_id).one()
    print(str(event_to_edit.date).replace(' ', 'T'))
    formatted_date = str(event_to_edit.date).replace(' ', 'T')
    if request.method == 'POST':
        edit_event_administraion.size=request.form['size']
        date_in=request.form['date']
        date_processing = date_in.replace('T', '-').replace(':', '-').split('-')
        date_processing = [int(v) for v in date_processing]
        edit_event_administraion.date = datetime.datetime(*date_processing)
        edit_event_administraion.topic=request.form['topic']
        edit_event_administraion.details=request.form['details']
        edit_event_administraion.address=request.form['address']
        edit_event_administraion.city=request.form['city']
        edit_event_administraion.state=request.form['state']
        edit_event_administraion.zipcode=request.form['zipcode']
        edit_event_administraion.cost=request.form['cost']
        edit_event_administraion.user_id = login_session['user_id']
        session.commit()
        activity = "Event on "+ edit_event_administraion.topic +" edited"
        newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
        session.add(newLog)
        session.commit()
        flash('Thanks for reaching out to me, I will contact you shortly. Darylin')
        return redirect(url_for('events'))
    else:
        resp = make_response(render_template('edit_events_admin.html', event=event_to_edit, formatted_date=formatted_date, user=user))
        return resp


@app.route('/admin/blog/<int:user>/edit/<int:blog_id>/',  methods=['GET', 'POST'])
def edit_blogs_admin(user,blog_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    blogs_to_edit = session.query(Blog).filter_by(id = blog_id).one()
    if request.method == 'POST':        
        blogs_to_edit.headline=request.form['headline']
        blogs_to_edit.hook=request.form['hook']
        blogs_to_edit.content=request.form['content']
        session.commit()
        activity = "Blog edited on " + blogs_to_edit.headline
        newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
        session.add(newLog)
        session.commit()
        flash('Your blog has been edited!!')
        return redirect(url_for('blog'))
    else:
        resp = make_response(render_template('edit_blogs_admin.html', blog=blogs_to_edit, user=user))
        return resp

@app.route('/admin/users/')
def user_administraion():
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    users = session.query(User).all()
    resp = make_response(render_template('user_admin.html', users=users))
    return resp

@app.route('/admin/correspondence/<int:user>/')
def correspondence_administraion(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    correspondence = session.query(Correspondence).all()
    resp = make_response(render_template('correspondence_admin.html', user=user, correspondence=correspondence))
    return resp

@app.route('/admin/tickets/<int:user>/')
def ticket_administraion(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    tickets = session.query(Ticket).all()
    users = session.query(User).all()
    events = session.query(Event).all()
    resp = make_response(render_template('ticket_admin.html', users=users, events=events, tickets=tickets))
    return resp

@app.route('/admin/testimonials/<int:user>/')
def testimonial_administraion(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    testimonials = session.query(Testimonial).all()
    users = session.query(User).all()
    resp = make_response(render_template('testimonial_admin.html', testimonials=testimonials, users = users))
    return resp

@app.route('/admin/blogs/<int:user>/')
def blog_administraion(user):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    blogs = session.query(Blog).all()
    resp = make_response(render_template('blog_admin.html', user=user, blogs=blogs))
    return resp

@app.route('/admin/logs/')
def log_administraion():
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    users = session.query(User).all()
    logs = session.query(Log).order_by(Log.id.desc()).all()
    resp = make_response(render_template('log_admin.html', users=users, logs=logs))
    return resp

@app.route('/admin/testimonial/detete/<int:testimonial_id>/')
def detete_testimonial(testimonial_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    testimonials_to_delete = session.query(Testimonial).filter_by(id = testimonial_id).one()
    activity = "Testimonial delete on " + testimonials_to_delete.topic
    newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
    session.add(newLog)
    session.delete(testimonials_to_delete)
    session.commit()
    resp = redirect(url_for('testimonial_administraion', user= login_session['user_id']))
    return resp

@app.route('/admin/event/<int:user>/cancel/<int:event_id>/')
def delete_event_administraion(user, event_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    event_to_delete = session.query(Event).filter_by(id = event_id).one()
    tickets = session.query(Ticket).filter_by(event_id= event_to_delete.id).all()
    events = session.query(Event).all()
    for ticket in tickets:
        user = session.query(User).filter_by(id=ticket.event_id).one()
        activity = ''
        activity += str(ticket.quantity) + ' tickets refunded to ' + user.email
        newLog = Log(timestamp= datetime.datetime.today(), user_id= 0, activity=activity)
        session.add(newLog)
        session.delete(ticket)
    session.delete(event_to_delete)
    session.commit()
    resp = make_response(render_template('events_admin.html', user=user,  events=events))
    return resp

@app.route('/admin/blog/detete/<int:blog_id>/')
def detete_blog(blog_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    blogs_to_delete = session.query(Blog).filter_by(id = blog_id).one()
    activity = "blog delete on " + blogs_to_delete.headline
    newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
    session.add(newLog)
    session.delete(blogs_to_delete)
    session.commit()

    resp = redirect(url_for('blog_administraion', user= login_session['user_id']))
    return resp

@app.route('/admin/correspondence/detete/<int:correspondence_id>/')
def detete_correspondence(correspondence_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        resp = make_response(render_template('main_page.html'))
        return resp
    correspondence_to_delete = session.query(Correspondence).filter_by(id = correspondence_id).one()
    activity = "correspondence delete my " + correspondence_to_delete.email
    newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
    session.add(newLog)
    session.delete(correspondence_to_delete)
    session.commit()
    resp = redirect(url_for('correspondence_administraion', user= login_session['user_id']))
    return resp

@app.route('/admin/user/detete/<int:user_id>/')
def detete_user(user_id):
    if 'user_id' not in login_session or login_session['user_id'] not in ADMINISTRATION_PROFILES:
        if login_session['user_id'] != user:
            resp = make_response(render_template('main_page.html'))
            return resp
    if login_session['user_id'] != user_id:
        user_to_delete = session.query(User).filter_by(id = user_id).one()
        activity = "user "+ user_to_delete.name +"deleted"
        newLog = Log(timestamp= datetime.datetime.today(), user_id= login_session['user_id'], activity=activity)
        session.add(newLog)
        session.delete(user_to_delete)
        session.commit()
        resp = redirect(url_for('user_administraion', user= login_session['user_id']))
        return resp
    else:
        flash("You are now logged in as %s. Login as a different user to delete this account." % login_session['username'])
        resp = redirect(url_for('user_administraion', user= login_session['user_id']))
        return resp

@app.route('/api/')
def api():
    resp = redirect(url_for('api_docs.html'))
    return resp


@app.errorhandler(404)
def not_found(error):
    resp = make_response(render_template('not_found.html'))
    return resp

if __name__ == '__main__':
    client_secret = "7waNwWUO1iMUsSQZC5fl-2F8"
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    #app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 ** 2
    app.secret_key = '\x86\x80\xa9\x1c\xff\x9c\xb4\xd4\xd8\x98\x16!n]\xe4\x8eW\x17t\xa8U\xeee\xef'
    SECRET_KEY = '\x86\x80\xa9\x1c\xff\x9c\xb4\xd4\xd8\x98\x16!n]\xe4\x8eW\x17t\xa8U\xeee\xef'
    app.config['SECURITY_PASSWORD_SALT']= 'bqJbw1eJRHZC5hm3'
    app.debug = True
    context = ('ssl.cert', 'ssl.key')
    app.run()#host='127.0.0.1', port=8080)#, ssl_context=context, threaded=True)
    

# set the secret key.  keep this really secret:
