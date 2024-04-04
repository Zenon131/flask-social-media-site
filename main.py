from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory, Blueprint, jsonify
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, URL, AnyOf, EqualTo, Email, Length
from flask_wtf.csrf import CSRFProtect
import secrets
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy.orm import relationship, joinedload
from functools import wraps
import datetime
from flask_ckeditor import CKEditor, CKEditorField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_uploads import UploadSet, IMAGES, configure_uploads
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
import os
from sqlalchemy.exc import IntegrityError



secretkey = secrets.token_hex(16)
api_id = "f5c911e8"

app = Flask(__name__, static_url_path='/static')
app.config["SECRET_KEY"] = secretkey
photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads/photos'
configure_uploads(app, photos)
Bootstrap5(app)
csrf = CSRFProtect(app)
ckeditor = CKEditor(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///epsilon11111.db'
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


cities = ['New York, NY', 'Palo Alto, CA', 'Boston, MA', 'Philadelphia, PA', 'Los Angeles, CA', 'San Franciso, CA']


class CommentForm(FlaskForm):
    comment_text = TextAreaField("Comment", validators=[Length(max=50)])
    submit = SubmitField("Comment")

class MessageForm(FlaskForm):
    message_text = TextAreaField("Say Something", validators=[Length(max=50)])
    submit = SubmitField("Send")


class OptinForm(FlaskForm):
    optin_text = StringField('Thoughts?')
    submit = SubmitField('Comment')


class ReplyForm(FlaskForm):
    reply_text = TextAreaField("Reply")
    submit = SubmitField("Reply")


class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email(), Length(max=40)])
    password = PasswordField(validators=[DataRequired(), Length(max=20)])
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    name = StringField(validators=[DataRequired(), Length(max=50)])
    contactinfo = StringField(validators=[DataRequired(), Length(max=20)])
    visibility = SelectField('Account Visibility', choices=['Public', 'Anonymous'], validators=[DataRequired()])
    location = SelectField('Select Your First Anchor Point', choices=cities, validators=[AnyOf(cities, message='Invalid city selection')])
    submit = SubmitField('Register')


class CafeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=20)])
    email = StringField('New Email', validators=[DataRequired()])
    contactinfo = StringField('Preferred method(s) of contact e.g. phone number, email address, IG, etc.', validators=[DataRequired()])
    bio = StringField('Bio', validators=[Length(max=50)])
    location = SelectField('Anchor Point', choices=['Change Your Anchor Point...'] + cities, validators=[AnyOf(cities, message='Invalid city selection')])
    visibility = SelectField('Account Visibility', choices=['Public', 'Anonymous'], validators=[DataRequired()])
    submit = SubmitField('Enter')


class CreateCommunityForm(FlaskForm):
    name = StringField('Community Name', validators=[DataRequired(), Length(max=20)])
    description = TextAreaField('Community Description', validators=[Length(max=150)])
    values = StringField('Community Values', validators=[DataRequired(), Length(max=50)])
    location = SelectField('Community Anchor Point (Cannot Be Changed Later)', choices=['Select Community Anchor Point...'] + cities, validators=[AnyOf(cities, message='Invalid city selection')])
    submit = SubmitField('Create')
    

user_community_association = db.Table(
    'user_community_association',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('community_id', db.Integer, db.ForeignKey('communities.id'))
)


class Community(db.Model):
    __tablename__ = "communities"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text)
    values = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    creator = relationship("User", back_populates="created_communities")


class CreateCircleForm(FlaskForm):
    name = StringField('Circle Name', validators=[DataRequired(), Length(max=20)])
    description = TextAreaField('Circle Description', validators=[Length(max=150)])
    submit = SubmitField('Create')


user_circle_association = db.Table(
    'user_circle_association',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('circle_id', db.Integer, db.ForeignKey('circles.id'))
)


class Circle(db.Model):
    __tablename__ = "circles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    creator = relationship("User", back_populates="created_circles")
    members = relationship("User", secondary="circle_membership", back_populates="joined_circles")
    messages = relationship("Message", back_populates="parent_circle")


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    postto = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text(50), nullable=False)
    postedfrom = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now())
    photo_filename = db.Column(db.String(255))
    photo_url = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


class Event(db.Model):
    __tablename__ = "events"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text(50), nullable=False)
    location = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship("User", back_populates="events")
    optins = relationship("Optin", back_populates="parent_event")


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=20)])
    postedfrom = StringField('Posted From...', validators=[DataRequired(), Length(max=50)])
    content = TextAreaField('Content', validators=[DataRequired(), Length(max=300)])
    postto = StringField('Post To...', validators=[DataRequired(), Length(max=50)])
    photo = FileField('Upload Photo', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Post')


class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    time = StringField('Time', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Post')


class StatusForm(FlaskForm):
    status = StringField('WYA?')
    submit = SubmitField('Update')


class Status(db.Model):
    __tablename__ = "status"
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now())
    user = relationship("User", back_populates="status")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now())
    parent_post = relationship("Post", back_populates="comments")


class Message(db.Model):
    __tablename__ = "messagess"
    id = db.Column(db.Integer, primary_key=True)
    message_text = db.Column(db.Text(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    messager = relationship("User", back_populates="messages")
    circle_id = db.Column(db.Integer, db.ForeignKey("circles.id"))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now())
    parent_circle = relationship("Circle", back_populates="messages")


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    is_read = db.Column(db.Boolean, default=False)


class Optin(db.Model):
    __tablename__ = "optins"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    opter = relationship("User", back_populates="optins")
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"))
    parent_event = relationship("Event", back_populates="optins")


# class Reply(db.Model):
#     __tablename__ = "replies"
#     id = db.Column(db.Integer, primary_key=True)
#     text = db.Column(db.Text, nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
#     reply_author = relationship("User", back_populates="replies")
#     post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
#     parent_comment = relationship("Comment", back_populates="replies")


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(20), unique=True, nullable=False)
    display_name = db.Column(db.String(20), unique=True, nullable=True)
    visibility = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    contactinfo = db.Column(db.String(80), unique=True, nullable=False)
    bio = db.Column(db.String(80))
    location = db.Column(db.String(120), nullable=False)
    comments = relationship("Comment", back_populates="comment_author")
    messages = relationship("Message", back_populates="messager")
    optins = relationship("Optin", back_populates="opter")
    posts = relationship("Post", back_populates="user")
    events = relationship("Event", back_populates="user")
    status = relationship("Status", back_populates="user")
    created_communities = relationship("Community", back_populates="creator", lazy="dynamic")
    joined_circles = relationship("Circle", secondary="circle_membership", back_populates="members")
    created_circles = relationship("Circle", back_populates="creator")

circle_membership = db.Table(
    'circle_membership',
    db.metadata,
    db.Column('user_id', db.Integer, ForeignKey('users.id')),
    db.Column('circle_id', db.Integer, ForeignKey('circles.id'))
)

with app.app_context():
    db.create_all()

    home_community = Community.query.filter_by(name='Home').first()
    if not home_community:
        home_community = Community(
            name='Home',
            description='Default community',
            values='Default Values',
            creator_id=None,
            location="New York, NY" # test different locations to verify intended behavior
        )
        db.session.add(home_community)
        db.session.commit()


#---------------------------------------------------------------------ROUTES---------------------------------------------------------------------#
@app.route("/")
def home():
    return render_template('index.html')



@app.route('/submit_comment<int:post_id>', methods=['POST'])
def submit_comment(post_id):
    # Process the form data
    comment_text = request.form.get('comment_text')
    comment_author = request.form.get('comment_author')
    requested_post = db.get_or_404(Post, post_id)

    if current_user.is_authenticated:
        new_comment = Comment(
            text=comment_text,
            comment_author=current_user,
            parent_post=requested_post
        )

        # Save the comment to the database
        db.session.add(new_comment)
        db.session.commit()

        user_name = current_user.name
        comment_timestamp = datetime.datetime.now()

        if requested_post.user != current_user:
            notification = Notification(
                message=f"New reply to '{requested_post.title}'",
                user_id=requested_post.user.id,
                post_id=requested_post.id
            )
            db.session.add(notification)
            db.session.commit()

        # Return a JSON response
        return jsonify(success=True, comment_text=comment_text, comment_author_name=user_name, timestamp=comment_timestamp)
    else:
        # Handle the case where the user is not authenticated
        return jsonify(success=False, message="User is not authenticated")



@app.route('/send_message<int:circle_id>', methods=['POST'])
def send_message(circle_id):
    # Process the form data
    message_text = request.form.get('message_text')
    messager = request.form.get('messager')
    requested_circle = db.get_or_404(Circle, circle_id)

    if current_user.is_authenticated:
        new_message = Message(
            message_text=message_text,
            messager=current_user,
            parent_circle=requested_circle
        )

        # Save the message to the database
        db.session.add(new_message)
        db.session.commit()

        user_name = current_user.name
        message_timestamp = datetime.datetime.now()

        # Return a JSON response
        return jsonify(success=True, message_text=message_text, messager=user_name, timestamp=message_timestamp)
    else:
        # Handle the case where the user is not authenticated
        return jsonify(success=False, message="User is not authenticated")



@app.route('/profile', methods=["GET", "POST"])
@login_required
def edit_profile():
    form = CafeForm()
    
    user = User.query.filter_by(email=current_user.email).first()

    if form.validate_on_submit():
        if user:

            user.name = form.name.data
            user.email = form.email.data
            user.contactinfo = form.contactinfo.data
            user.bio = form.bio.data
            user.location = form.location.data
            user.visibility = form.visibility.data
            user.display_name = form.name.data if form.visibility.data == "Public" else "Anonymous"

            db.session.commit()
            flash('User data updated successfully!', 'success')
            return redirect(url_for('show_profile', user_id=current_user.id))
        else:
            flash('User not found!', 'danger')

    form.name.data = user.name
    form.email.data = user.email
    form.contactinfo.data = user.contactinfo
    form.bio.data = user.bio
    form.location.data = user.location
    form.visibility.data = user.visibility


    return render_template('edit_profile.html', form=form, email=current_user.email, logged_in=current_user.is_authenticated)



@app.route('/profile/<int:user_id>', methods=["GET", "POST"])
@login_required
def show_profile(user_id):
    requested_user = db.get_or_404(User, user_id)
    username = requested_user.display_name
    
    return render_template('profile.html', name=username, user=requested_user, logged_in=current_user.is_authenticated)



@app.route('/community-feed', methods=["GET", "POST"])
@login_required
def commfeed():
    form = StatusForm()

    if form.validate_on_submit():
        status_update = Status(
            status=form.status.data,
            user_id=current_user.id
            )
        db.session.add(status_update)
        db.session.commit()

    posts = Post.query.filter_by(postto='Home').all()
    events = Event.query.all()
    combined_entries = sorted(posts + events, key=lambda entry: entry.timestamp, reverse=True)

    status = db.session.query(Status).order_by(Status.id.desc()).first()
    form.status.data = ""
    communities = Community.query.all()

    home_community.location = current_user.location
    db.session.commit()

    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(5).all()

    return render_template("commfeed.html", communities=communities, form=form, status=status, entries=combined_entries, notifications=notifications, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route('/community/<int:community_id>', methods=["GET", "POST"])
@login_required
def community_page(community_id):
    form = StatusForm()

    if form.validate_on_submit():
        status_update = Status(
            status=form.status.data,
            user_id=current_user.id
        )
        db.session.add(status_update)
        db.session.commit()

    community = Community.query.get(community_id)
    community_posts = Post.query.filter_by(postto=community.name).all()
    events = Event.query.all()
    combined_entries = sorted(community_posts + events, key=lambda entry: entry.timestamp, reverse=True)
    communities = Community.query.all()

    status = db.session.query(Status).order_by(Status.id.desc()).first()
    form.status.data = ""

    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(5).all()

    return render_template("community.html", form=form, status=status, community=community, communities=communities, notifications=notifications, entries=combined_entries, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route('/circle/<int:circle_id>', methods=["GET", "POST"])
@login_required
def circle_page(circle_id):
    form = StatusForm()

    if form.validate_on_submit():
        status_update = Status(
            status=form.status.data,
            user_id=current_user.id
        )
        db.session.add(status_update)
        db.session.commit()
    
    status = db.session.query(Status).order_by(Status.id.desc()).first()
    form.status.data = ""

    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(5).all()

    circle = Circle.query.get(circle_id)
    circles = current_user.joined_circles
    messages = circle.messages

    message_form = MessageForm()

    if message_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_message = Message(
            message_text=message_form.message_text.data,
            messager=current_user,
            parent_circle=circle,
            timestamp = datetime.datetime.now()
        )
        db.session.add(new_message)
        db.session.commit()


        message_form.message_text.data = ""

    if circle:
        if current_user not in circle.members:
            circle.members.append(current_user)
            db.session.commit()
            
        return render_template("circle.html", form=form, message_form=message_form, status=status, circle=circle, circles=circles, messages=messages, notifications=notifications, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route('/create-community', methods=["GET", "POST"])
@login_required
def create_community():
    form = CreateCommunityForm()

    if form.validate_on_submit():
        new_community = Community(
            name=form.name.data,
            description=form.description.data,
            values=form.values.data,
            creator=current_user,
            creator_id=current_user.id,
            location=form.location.data
        )
        db.session.add(new_community)
        db.session.commit()
        flash('Community created successfully!', 'success')
        return redirect(url_for('community_page', community_id=new_community.id))

    return render_template('make-community.html', form=form, logged_in=current_user.is_authenticated)



@app.route('/create-circle', methods=["GET", "POST"])
@login_required
def create_circle():
    form = CreateCircleForm()

    if form.validate_on_submit():
        new_circle = Circle(
            name=form.name.data,
            description=form.description.data,
            creator=current_user
        )
        db.session.add(new_circle)
        db.session.commit()
        flash('Community created successfully!', 'success')
        return redirect(url_for('circle_page', circle_id=new_circle.id))

    return render_template('make-circle.html', form=form, logged_in=current_user.is_authenticated)



@app.route('/close_community/<int:community_id>', methods=["GET", "DELETE"])
def close_community(community_id):
    community = db.get_or_404(Community, community_id)
    db.session.delete(community)
    db.session.commit()
    flash('Community deleted successfully.', 'success')
    return redirect(url_for('explore_communities'))



@app.route('/explore_communities')
@login_required
def explore_communities():
    all_communities = Community.query.all()
    created_communities = current_user.created_communities

    return render_template('explore-communities.html', all_communities=all_communities, created_communities=created_communities, logged_in=current_user.is_authenticated)



@app.route('/my_circles')
@login_required
def my_circles():
    all_circles = current_user.joined_circles

    return render_template('my-circles.html', all_circles=all_circles, logged_in=current_user.is_authenticated)



@app.route('/events-feed')
@login_required
def eventsfeed():
    form = StatusForm()

    if form.validate_on_submit():
        status_update = Status(
            status=form.status.data,
            user_id=current_user.id
        )
        db.session.add(status_update)
        db.session.commit()

    result = db.session.query(Event).order_by(Event.id.desc())
    events = result.all()

    status = db.session.query(Status).order_by(Status.id.desc()).first()
    form.status.data = ""
    return render_template("eventsfeed.html", form=form, entries=events, status=status, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route('/psas')
@login_required
def psas():
    form = StatusForm()

    if form.validate_on_submit():
        status_update = Status(
            status=form.status.data,
            user_id=current_user.id
        )
        db.session.add(status_update)
        db.session.commit()

    result = db.session.query(Post).order_by(Post.id.desc())
    posts = result.all()

    status = db.session.query(Status).order_by(Status.id.desc()).first()
    form.status.data = ""
    return render_template("psas.html", status=status, form=form, enrties=posts, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route('/peeps')
@login_required
def peeps():
    return render_template("peeps.html", current_user=current_user, logged_in=current_user.is_authenticated)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():

        # Check if the email is already taken
        existing_user_email = User.query.filter_by(email=form.email.data).first()
        if existing_user_email:
            flash("Email is already taken. Please choose another email.")
            return redirect(url_for('register'))

        # Check if the name is already taken
        existing_user_name = User.query.filter_by(name=form.name.data).first()
        if existing_user_name:
            flash("Username is already taken. Please choose another username.")
            return redirect(url_for('register'))

        # Check if the contactinfo is already taken
        existing_user_contactinfo = User.query.filter_by(contactinfo=form.contactinfo.data).first()
        if existing_user_contactinfo:
            flash("Contact information is already taken. Please choose another contact information.")
            return redirect(url_for('register'))

        # Hash and salt the password
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=12
        )

        # Create a new user
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            contactinfo=form.contactinfo.data,
            password=hash_and_salted_password,
            location=form.location.data,
            visibility=form.visibility.data,
            display_name = form.name.data if form.visibility.data == "Public" else "Anonymous"
        )

        # Attempt to add the new user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Registration successful!', 'success')
            return redirect(url_for("commfeed"))
        except IntegrityError as e:
            # Handle database constraint violation (e.g., unique constraint)
            db.session.rollback()
            flash("Registration failed. Please choose unique values for email, username, and contact information.")
            return redirect(url_for('register'))

    return render_template("reg.html", form=form, current_user=current_user)



@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(Post, post_id)
    body = requested_post.content
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post,
            timestamp = datetime.datetime.now()
        )
        db.session.add(new_comment)
        db.session.commit()


        comment_form.comment_text.data = ""
    return render_template("post.html", post=requested_post, current_user=current_user, comform=comment_form, body=body, logged_in=current_user.is_authenticated)



@app.route("/community-post/<int:post_id>", methods=["GET", "POST"])
def show_community_post(post_id):
    requested_post = db.get_or_404(Post, post_id)
    body = requested_post.content
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()


        comment_form.comment_text.data = ""
    return render_template("post.html", post=requested_post, current_user=current_user, comform=comment_form, body=body, logged_in=current_user.is_authenticated)



@app.route("/event/<int:event_id>", methods=["GET", "POST"])
def show_event(event_id):
    requested_event = db.get_or_404(Event, event_id)
    body = requested_event.description
    optin_form = OptinForm()

    if optin_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to optin.")
            return redirect(url_for("login"))

        new_optin = Optin(
            text=optin_form.optin_text.data,
            opter=current_user,
            parent_event=requested_event
        )
        db.session.add(new_optin)
        db.session.commit()
        optin_form.optin_text.data = ""
    return render_template("event.html", event=requested_event, current_user=current_user, optin_form=optin_form, body=body, logged_in=current_user.is_authenticated)



@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(Post, post_id)
    edit_form = PostForm(
        title=post.title,
        postedfrom=post.postedfrom,
        content=post.content,
        user_id=current_user.id
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data,
        post.postedfrom = edit_form.postedfrom.data,
        post.user_id = current_user.id,
        post.content = edit_form.content.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)



@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('commfeed'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)




@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')

    # Implement your search logic based on the entire dataset
    # For each result, determine the type (person, post, community)
    # Return results as JSON
    results = [
        {'type': 'person', 'username': 'example_user'},
        {'type': 'post', 'post': 'example_post_content'},
        {'type': 'community', 'community': 'example_community'},
        # Add more results as needed
    ]

    return jsonify(results)



@app.route('/uploads/<filename>')
def get_file(filename):
    return send_from_directory(app.config['UPLOADED_PHOTOS_DEST'], filename)



@app.route("/make-post", methods=["GET", "POST"])
@login_required
def post():
    form = PostForm()
    
    if form.validate_on_submit():
        # Find the community with the specified name
        community_name = form.postto.data
        community = Community.query.filter_by(name=community_name).first()
        print(form.photo.data)

        if community:
            # Create the post and associate it with the community
            post = Post(
                title=form.title.data,
                content=form.content.data,
                postedfrom = form.postedfrom.data,
                user=current_user,
                postto=community.name,
                location=current_user.location,
                timestamp = datetime.datetime.now()
            )
        
            # Handle file upload
            if form.photo.data:
                fn = photos.save(form.photo.data)
                post.photo_filename = fn
                post.photo_url = url_for('get_file', filename=fn)
                print(fn)

            db.session.add(post)
            db.session.commit()

            flash('Post created successfully!', 'success')
            if community_name != "Home":
                return redirect(url_for('community_page', community_id=community.id))
            else:
                return redirect(url_for('commfeed'))

        flash('Community not found. Please enter a valid community name.', 'danger')
    return render_template("make-post.html", form=form, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route("/make-event", methods=["GET", "POST"])
@login_required
def event():
    form = EventForm()

    if form.validate_on_submit():
        new_event = Event(
            title=form.title.data,
            location=form.location.data,
            time=form.time.data,
            description=form.description.data,
            user_id=current_user.id
        )
        db.session.add(new_event)
        db.session.commit()
        flash('Event added successfully!', 'success')
        return redirect(url_for('commfeed'))

    events = Event.query.all()

    return render_template("make-event.html", form=form, events=events, current_user=current_user, logged_in=current_user.is_authenticated)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)