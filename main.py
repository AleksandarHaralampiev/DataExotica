from flask import Flask, render_template, request, make_response, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
from email.message import EmailMessage
import ssl
import smtplib
import random
import requests
from bs4 import BeautifulSoup
import json
from newsapi.newsapi_client import NewsApiClient
import string
from urllib.parse import urlparse
from cryptography.fernet import Fernet, InvalidToken
import openai
from dotenv import load_dotenv


load_dotenv()
#2fa configuration

openai.api_key = os.getenv("OPENAI_API_KEY")

INSTRUCTIONS = """You are an AI assistant that is a cybersecurity expert. You know all about the different cyber attacks and cyber protection. You can advise how to prevent cyber attacks, what to do if the user is attacked and answer questions about cybersecurity. If you are unable to provide an answer to a question or the question is not associated with cybersecurity, please respond with the phrase: I'm just a cybersecurity expert, I can't help with that. Do not use any external URLs in your answers. Do not refer to any blogs in your answers. Do not format any lists on individual lines. Instead, format them as a single line. Don't use numbers to seperate items in a list. Use First, Second, Third... Never answer other questions except cybersecurity."""
TEMPERATURE = 0.5
MAX_TOKENS = 500
FREQUENCY_PENALTY = 0
PRESENCE_PENALTY = 0.6
MAX_CONTEXT_QUESTIONS = 10
previous_questions_and_answers = []


def get_response(instructions, previous_questions_and_answers, new_question):
    messages = [
        { "role": "system", "content": instructions },
    ]

    for question, answer in previous_questions_and_answers[-MAX_CONTEXT_QUESTIONS:]:
        messages.append({ "role": "user", "content": question })
        messages.append({ "role": "assistant", "content": answer })
    
    messages.append({ "role": "user", "content": new_question })

    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
        top_p=1,
        frequency_penalty=FREQUENCY_PENALTY,
        presence_penalty=PRESENCE_PENALTY,
    )

    return completion.choices[0].message.content


def get_moderation(question):
    errors = {
        "hate": "Content that expresses, incites, or promotes hate based on race, gender, ethnicity, religion, nationality, sexual orientation, disability status, or caste.",
        "hate/threatening": "Hateful content that also includes violence or serious harm towards the targeted group.",
        "self-harm": "Content that promotes, encourages, or depicts acts of self-harm, such as suicide, cutting, and eating disorders.",
        "sexual": "Content meant to arouse sexual excitement, such as the description of sexual activity, or that promotes sexual services (excluding sex education and wellness).",
        "sexual/minors": "Sexual content that includes an individual who is under 18 years old.",
        "violence": "Content that promotes or glorifies violence or celebrates the suffering or humiliation of others.",
        "violence/graphic": "Violent content that depicts death, violence, or serious physical injury in extreme graphic detail.",
    }

    response = openai.Moderation.create(input=question)

    if response.results[0].flagged:
        result = [
            error
            for category, error in errors.items()
            if response.results[0].categories[category]
        ]
        return result
    
    return None

def get_answer(new_question):
    errors = get_moderation(new_question)
    if errors:
        return "Sorry, you're question didn't pass the moderation check"
    
    response = get_response(INSTRUCTIONS, previous_questions_and_answers, new_question)
    
    previous_questions_and_answers.append((new_question, response))
    
    return response


email_sender = os.environ.get('EMAIL_SENDER')
email_password = os.environ.get('EMAIL_PASSWORD')


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)
key = Fernet.generate_key()
crypter = Fernet(key)



# Models
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer(), primary_key = True)
    email = db.Column(db.String(), unique = True, nullable = False)
    username = db.Column(db.String(), unique = True, nullable = False)
    password = db.Column(db.String(), nullable = False)
    
class Item(db.Model):
    __tablename__ = 'password'
    id = db.Column(db.Integer(), primary_key = True)
    email = db.Column(db.String(), nullable = False)
    username = db.Column(db.String(), nullable = False)
    user_password = db.Column(db.String(), nullable = False)
    website = db.Column(db.String(), nullable = False)

class Blog(db.Model):
    __tablename__ = 'blog'
    id = db.Column(db.Integer(), primary_key = True)
    user = db.Column(db.String(), nullable = False)
    title = db.Column(db.String(), nullable = False)
    description = db.Column(db.String(), nullable = False)
    views = db.Column(db.Integer, default=0)
    comments = db.Column(db.Integer, default=0)

class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer(), primary_key = True)
    comment = db.Column(db.String(), nullable = False)
    sender = db.Column(db.String(), nullable = False)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    post = db.Column(db.String(), nullable = False)

# Routes
@app.route('/')
@app.route('/home')
def home():
    email = session.get('email')
    if email:
        return redirect(url_for('Index'))
    newsapi = NewsApiClient(api_key= os.getenv('NEWS_API_KEY'))
    topheadlines = newsapi.get_everything(q='cybersecurity',
                                          language='en',
                                          sort_by = 'publishedAt',
                                          page_size=5
                                          )
                                        
    articles = topheadlines['articles']

    desc = []
    news = []
    link = []
    img = []


    for i in range(len(articles)):
        myarticles = articles[i]


        news.append(myarticles['title'])
        desc.append(myarticles['content'])
        img.append(myarticles['urlToImage'])
        link.append(myarticles['url'])



    mylist = zip(news, desc, link, img)

    return render_template('home.html', context = mylist)



@app.route('/register', methods = ["POST", "GET"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        psw = request.form.get("password")
        psw_confirm = request.form.get("confirm_password")
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('register.html', message="Another account is using this email.")
        elif len(email) < 4:
            return render_template('register.html', message="Email must be longer than 3 characters.")
        elif len(username) < 2:
            return render_template('register.html', message="Username must be longer than 2 characters.")
        elif psw != psw_confirm:
            return render_template('register.html', message="The passwords do not match.")
        elif len(psw) < 7:
            return render_template('register.html', message="The password must be at least 7 characters")
        else:
            hash_object = hashlib.sha256(psw.encode('utf-8'))
            hex_dig = hash_object.hexdigest()
            user = User(email=email, username=username, password = hex_dig)
            db.session.add(user)
            db.session.commit()
            flash('Account created!', category='success')
            return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    email = session.get('email')
    if email:
        return redirect(url_for('verification'))
    if request.method == 'POST':
        email = request.form['email']
        email_receiver = email
        code = random.randint(100000, 999999)
        session['code'] = code  # store code in session

        subject = 'Verification Code'
        body = f'Your verification code is: \n----------\n{code}\n----------'

        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(email_sender, email_password)
            server.sendmail(email_sender, email_receiver, em.as_string())
        password = request.form['password']
        remember = request.form.get('remember', False)
        session['remember'] = remember
        user = User.query.filter_by(email=email).first()
        if user is None:
            return render_template('login.html', message="Invalid Credentials")
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        if hash_password == user.password:
            session['email'] = email
            session['password'] = password
            if remember:
                session.permanent = True
            return redirect(url_for('verification'))
        else:
            return render_template('login.html', message="Invalid Credentials")
    else:
        return render_template('login.html')

@app.route('/addpass', methods=['GET', 'POST'])
def addpass():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
        email = session['email']
        username = request.form['username']
        password = request.form['password']
        website = request.form['website']

        # Encrypt the password
        encrypted_password = crypter.encrypt(password.encode())

        # Create a new Item instance with the encrypted password
        item = Item(email=email,username=username, user_password=encrypted_password, website=website)
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('manager'))

    return render_template('addpass.html')

@app.route('/manager')
def manager():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    # Retrieve all items from the database
    email = session['email']
    users = Item.query.filter_by(email=email).all()    
    # Decrypt the passwords and create a list of dictionaries with the decrypted passwords
    decrypted_items = []
    for item in users:
        try:
            
            decrypted_password_b = crypter.decrypt(item.user_password)
            decrypted_password = (decrypted_password_b.decode())
            decrypted_item = {
                'id': item.id,
                'username': item.username,
                'password': decrypted_password,
                'website': item.website
            }
            decrypted_items.append(decrypted_item)
        except InvalidToken:
            print(f"Failed to decrypt item with id {item.id}")

        
    return render_template('manager.html', items=decrypted_items)




@app.route('/password_generator', methods=['POST', 'GET'])
def password_generator():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
        chars = ""
        length = request.form.get('length', default = 12)
        length = int(length)
        uppercase = request.form.get('uppercase', False)
        lowercase = request.form.get('lowercase', False)
        numbers = request.form.get('numbers', False)
        symbols = request.form.get('symbols', False)
        if uppercase != False:
            chars += string.ascii_uppercase
        if lowercase != False:
            chars += string.ascii_lowercase
        if numbers != False:
            chars += string.digits
        if symbols != False:
            chars += string.punctuation 
        if chars == "":
            message = "Something went wrong"
            return render_template('password_generator.html', message=message)
        password = ''.join(random.choices(chars, k=length))
        return render_template('password_generator.html', password=password)


    return render_template('password_generator.html')


@app.route('/password_checker', methods=["POST", "GET"])
def password_checker():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
            score = 0
            password = request.form.get('password', '')
            if password == None:
                return render_template('password_checker.html')
            if len(password) < 12:
                score += 1
            elif len(password) >= 12:
                score += 3
        # Check for presence of numbers, uppercase and lowercase letters
            has_digit = False
            has_uppercase = False
            has_lowercase = False
            for char in password:
                if char.isdigit():
                    has_digit = True
                elif char.isupper():
                    has_uppercase = True
                elif char.islower():
                    has_lowercase = True
    
            # Check if all character types are present
            if has_digit and has_uppercase and has_lowercase:
                score += 3
            elif (has_digit and has_uppercase) or (has_digit and has_lowercase) or (has_uppercase and has_lowercase):
                score += 2
            elif has_digit or has_uppercase or has_lowercase:
                score += 1
    
            # Add bonus points for special characters
            special_characters = "!@#$%^&*()-_=+[]{};:'\"<>,.?\\|/"
            has_special = False
            for char in password:
                if char in special_characters:
                    has_special = True
                    break
            if has_special:
                score += 4
            
            if (score <= 3):
                message = "The password is weak"
                emoji = "😭"
            elif(score <= 7):
                message = "The password is good"
                emoji = "😐"
            elif (score <= 9):
                message = "The password is strong"
                emoji = "😀"
            elif(score == 10):
                message = "The password is really strong"
                emoji = "💪"
            # Map score to a 1-10 scale
            width = score * 10
            width = str(width) + "%"
            return render_template('password_checker.html', score=score, message=message, width=width,emoji=emoji)
    return render_template('password_checker.html')







@app.route('/verification', methods=['GET', 'POST'])
def verification():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))    
    print("hello world")
    if request.method == 'POST':
        code= int(request.form['code'])
        if code == (session['code']):
            return redirect(url_for('Index'))
        else:   
            flash('Invalid Code')
            return render_template('auth.html')
    else:
        return render_template('auth.html')
    
@app.route('/lectures')
def lectures():
    return render_template('lectures.html')

@app.route('/phishing_1', methods=['GET', 'POST'])
def phishing_1():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
        login_email = request.form['login_email']
        login_password = request.form['login_password']
        session['login_email'] = login_email
        session['login_password'] = login_password
        
        
        
    return render_template('visualization.html')



@app.route('/lectures_1')
def lecture_1():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    return render_template('lecture_1.html')

@app.route('/phishing')
def phishing():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))

    return render_template('phishing.html')


@app.route('/logout')
def left():
    session.pop("email", None)
    session.pop("remember", None)
    session.pop("password", None)
    return redirect('/')

@app.route('/visualization', methods = ['POST', 'GET'])
def visualization():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    hacked = False
    if request.method == 'POST':
        email = request.form.get('login_email')
        password = request.form.get('login_password')
        hacked = True
        return render_template('visualization.html', email = email, password = password, hacked = hacked)
    return render_template('visualization.html')

@app.route('/dns_lookup', methods=['GET', 'POST'])
def dns_lookup():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
        url = request.form.get('url')
        dns_api_key = os.environ.get('DNS_LOOKUP_API_KEY')
        headers = {'x-api-key' : dns_api_key}
        mxtoolbox_url = f'https://api.geekflare.com/dnsrecord'
        payloat = {
            'url':url
        }
        response = requests.post(mxtoolbox_url, json=payloat, headers=headers)
        
        # soup = BeautifulSoup(response.text, 'html.parser')
        # result_div = soup.find('', {'': ''})
        
        
        output = response.json()
        
        # result_div = output
        apiCode = output['apiCode']
        if apiCode == 404:
            # return
            print("error 404")
            
        result_ip = output['data']['A'][0]['address']
        result_ttl = output['data']['A'][0]['ttl']
        result_txt = output['data']['TXT']
        result_txt_output = []
        for txt in output['data']['TXT']:
            result_txt_output.append(txt)
        
        if result_ip is not None:
            result_text = result_ip
        else:
            result_text = 'No results found.'
            
        if result_ttl is not None:
            result_text_one = result_ttl
        else:
            result_text_one = 'No results found.'

        result_div= None
        return render_template('dns_lookup.html', url=url, result=result_text, result_one = result_text_one, txt_result = result_txt_output )

    return render_template('dns_lookup.html')

@app.route('/link_checker', methods = ['POST', 'GET'])
def link_checker():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
        api_key = os.environ.get('LINK_CHECKER_API_KEY')
        url  = 'https://www.virustotal.com/vtapi/v2/url/report'
        website = request.form.get('url')
        if website is None:
            return render_template('link_checker.html')
        params = {'apikey': api_key, 'resource': website}
        response = requests.get(url, params=params)
        response_json = json.loads(response.content)
        if response_json['positives'] <= 0:
            message = "Safe"
            return render_template('link_checker.html', message=message)
        if response_json['positives'] >= 3:
            message = "Not Sure"
            return render_template('link_checker.html', message=message)
        if response_json['positives'] >= 4:
            message = "Malicious"
            return render_template('link_checker.html', message=message)
    else:
        return render_template('link_checker.html')
    

@app.route('/news', methods= ['POST', 'GET'])
def Index():
    newsapi = NewsApiClient(api_key=os.environ.get('NEWS_API_KEY'))
    topheadlines = newsapi.get_everything(q='cybersecurity',
                                          language='en',
                                          sort_by = 'publishedAt',
                                          page_size=5
                                          )
                                        
    articles = topheadlines['articles']

    desc = []
    news = []
    link = []
    img = []


    for i in range(len(articles)):
        myarticles = articles[i]


        news.append(myarticles['title'])
        desc.append(myarticles['content'])
        img.append(myarticles['urlToImage'])
        link.append(myarticles['url'])



    mylist = zip(news, desc, link, img)

    if request.method == 'POST':
        question = request.form.get('question')
        if not question:
            return render_template('news.html', context = mylist)
        answer = get_answer(question)
        if question and answer:
            return render_template('news.html', question = question, answer=answer, context = mylist)
    else :return render_template('news.html', context = mylist)
    return render_template('news.html', context = mylist)



@app.route('/blacklist', methods=['GET', 'POST'])
def blacklist():
    blacklist_api_key = os.environ.get('BLACKLIST_API_KEY')
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
        domain = request.form.get('mail')
        url = f"https://api.blacklistchecker.com/check/{domain}"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + blacklist_api_key
        }

        response = requests.request("GET", url, headers=headers)
        data = response.json()

        blacklisting = []
        names = []

        for item in data['blacklists']:
            names.append(item['name'])
            if item['detected'] == 'false':
                blacklisting.append('Blacklisted')
            else:
                blacklisting.append('Not blacklisted')

        package = zip(blacklisting, names)

        return render_template('blacklist.html', package=package)

    return render_template('blacklist.html', package=None)

@app.route('/blog')
def blog():
    posts = Blog.query.all()
    posts.reverse()
    return render_template("blog.html", posts=posts)

@app.route("/blog_add", methods=["POST", "GET"])
def blog_add():
    if request.method == "POST":
            email = session['email']
            acc = User.query.filter_by(email=email).first()
            user = acc.username
            title = request.form.get('title')
            description = request.form.get('description')
            blog = Blog(user=user, title=title, description=description)
            db.session.add(blog)
            db.session.commit()
            return redirect(url_for("blog"))
    return render_template("blog_add.html")
@app.route('/blog_view/<int:Post_id>', methods=["POST", "GET"])
def blog_view(Post_id):
    post = db.session.get(Blog, Post_id)
    if post:
        post_id = Post_id

    if request.method == "POST":
        comment = request.form.get("comment")
        post_id = Post_id
        email = session['email']
        acc = User.query.filter_by(email=email).first()
        sender = acc.username
        comd = Comment(comment=comment, post = post_id, sender=sender)
        db.session.add(comd)
        db.session.commit()
        return redirect(url_for("blog_view", Post_id=Post_id))
    comments = Comment.query.filter_by(post=post_id).all()
    comments.reverse()
    return render_template('blog_view.html', comments=comments, post=post)
@app.route('/like_comment', methods=['POST'])
def like_comment():
    comment_id = request.form['comment_id']
    comment = Comment.query.filter_by(id=comment_id).first()
    if comment:
        comment.likes += 1
        db.session.commit()
        return jsonify({'status': 'success', 'likes': comment.likes})
    else:
        return jsonify({'status': 'error', 'message': 'Comment not found'})

@app.route('/dislike_comment', methods=['POST'])
def dislike_comment():
    comment_id = request.form['comment_id']
    comment = Comment.query.filter_by(id=comment_id).first()
    if comment:
        comment.dislikes += 1
        db.session.commit()
        return jsonify({'status': 'success', 'dislikes': comment.dislikes})
    else:
        return jsonify({'status': 'error', 'message': 'Comment not found'})
@app.route('/blog_view/<int:Post_id>/view_count', methods=["POST", "GET"])
def update_view_count(Post_id):
    post = db.session.get(Blog, Post_id)
    if post:
        post.views += 1
        db.session.commit()
    return '', 204

if __name__ == "__main__":
    app.run(debug=True)