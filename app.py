from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from flask_wtf.file import FileField, FileAllowed
import os
from werkzeug.utils import secure_filename
import re
import html

# Flask App Setup
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus_bookshare.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Init extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to the login page if not authenticated
login_manager.login_message_category = 'info'
login_manager.remember_cookie_duration = timedelta(days=7)  # Users stay logged in for 7 days

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Load the user by ID

### MODELS ###

from flask_login import UserMixin

class User(db.Model, UserMixin):  # Inherit from UserMixin
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    verified = db.Column(db.Boolean, default=False)  # Add this field

    @property
    def name(self):
        return f"{self.first_name} {self.last_name}"  # Combine first and last name

    # Flask-Login requires these properties
    @property
    def is_active(self):
        return True  # Return True if the user account is active

    @property
    def is_authenticated(self):
        return True  # Return True if the user is authenticated

    @property
    def is_anonymous(self):
        return False  # Return False because this is not an anonymous user

    def get_id(self):
        return str(self.user_id)  # Return the unique identifier for the user

    @property
    def reputation_score(self):
        reviews = self.received_reviews
        if not reviews:
            return None
        return round(sum(review.rating for review in reviews) / len(reviews), 2)

class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    course_code = db.Column(db.String(20), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    availability = db.Column(db.String(20), nullable=False, default='Available')
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)  # Add this field

    # Relationships
    owner = db.relationship('User', backref='books')

class Reservation(db.Model):
    reservation_id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    date_reserved = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=False)
    pickup_location = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=True)

    # Relationships
    book = db.relationship('Book', backref='reservations')

    @property
    def is_overdue(self):
        return datetime.utcnow() > self.due_date

class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=True)
    topic = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    parent_id = db.Column(db.Integer, db.ForeignKey('message.message_id'), nullable=True)

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')
    replies = db.relationship('Message', backref=db.backref('parent', remote_side=[message_id]), lazy='joined')

class Review(db.Model):
    review_id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable=True)  # Nullable for lender reviews
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)  # User leaving the review
    reviewed_user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=True)  # User being reviewed
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    book = db.relationship('Book', backref='reviews', lazy='joined')
    reviewer = db.relationship('User', foreign_keys=[reviewer_id], backref='written_reviews')
    reviewed_user = db.relationship('User', foreign_keys=[reviewed_user_id], backref='received_reviews')

class Notification(db.Model):
    notification_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # Relationships
    user = db.relationship('User', backref='notifications')

### FORMS ###

def no_special_characters(form, field):
    if not re.match("^[a-zA-Z0-9 .'-]+$", field.data):  # Allows letters, numbers, spaces, ., ', and -
        raise ValidationError("Field contains invalid characters.")

class RegisterForm(FlaskForm):
    first_name = StringField(
        'First Name',
        validators=[
            DataRequired(message="First name is required."),
            Length(max=50, message="First name must be less than 50 characters."),
            no_special_characters
        ]
    )
    last_name = StringField(
        'Last Name',
        validators=[
            DataRequired(message="Last name is required."),
            Length(max=50, message="Last name must be less than 50 characters."),
            no_special_characters
        ]
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Please enter a valid email address."),
            Length(max=120, message="Email must be less than 120 characters."),
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=6, message="Password must be at least 6 characters long."),
            Regexp(
                r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$',
                message="Password must include at least one uppercase letter, one lowercase letter, one number, and one special character."
            )
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message="Confirm password is required."),
            EqualTo('password', message="Confirmed password does not match.")
        ]
    )
    submit = SubmitField('Register')

    # Custom validation for .edu email
    def validate_email(self, email):
        if not email.data.endswith('.edu'):
            raise ValidationError("Only .edu email addresses are allowed.")
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("This email is already registered.")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')  # Add this field
    submit = SubmitField('Login')

class MessageForm(FlaskForm):
    topic = StringField('Topic', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Message', validators=[DataRequired(), Length(max=500)])
    link = FileField('Attach a File (optional)', validators=[FileAllowed(['jpg', 'png', 'pdf', 'docx'], 'Files only!')])
    submit = SubmitField('Post Message')

class BookForm(FlaskForm):
    title = StringField(
        "Title",
        validators=[
            DataRequired(),
            Length(max=100, message="Title must be less than 100 characters."),
            no_special_characters
        ]
    )
    author = StringField(
        "Author",
        validators=[
            DataRequired(),
            Length(max=100, message="Author name must be less than 100 characters."),
            no_special_characters
        ]
    )
    ISBN = StringField(
        "ISBN",
        validators=[
            Length(max=20, message="ISBN must be less than 20 characters."),
            Regexp(r'^(97(8|9))?\d{9}(\d|X)$', message="Invalid ISBN format.")
        ]
    )
    subject = StringField(
        "Subject",
        validators=[
            DataRequired(),
            Length(max=50, message="Subject must be less than 50 characters."),
            no_special_characters
        ]
    )
    course_code = StringField(
        "Course Code",
        validators=[
            DataRequired(),
            Length(max=20, message="Course code must be less than 20 characters."),
            no_special_characters
        ]
    )
    condition = SelectField(
        "Condition",
        choices=[
            ("New", "New"),
            ("Like New", "Like New"),
            ("Good", "Good"),
            ("Fair", "Fair"),
            ("Poor", "Poor"),
        ],
        validators=[DataRequired()],
    )
    availability = SelectField(
        "Availability",
        choices=[("Available", "Available"), ("Unavailable", "Unavailable")],
    )
    submit = SubmitField("Save Changes")

class CreateListingForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    subject = StringField("Subject", validators=[DataRequired()])
    course_code = StringField("Course Code", validators=[DataRequired()])
    condition = SelectField(
        "Condition",
        choices=[
            ("New", "New"),
            ("Like New", "Like New"),
            ("Good", "Good"),
            ("Fair", "Fair"),
            ("Poor", "Poor"),
        ],
        validators=[DataRequired()],
    )
    availability = SelectField(
        "Availability",
        choices=[("Available", "Available"), ("Unavailable", "Unavailable")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Create Listing")

class ReviewForm(FlaskForm):
    rating = SelectField(
        'Rating (1-5)',
        choices=[(1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5')],
        validators=[
            DataRequired(),
            Regexp(r'^[1-5]$', message="Rating must be a number between 1 and 5.")
        ]
    )
    content = TextAreaField('Review', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Submit Review')

### ROUTES ###

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    listings = Book.query.order_by(Book.date_posted.desc()).limit(5).all()
    return render_template('index.html', listings=listings)

@app.route('/home')
@login_required
def home():
    listings = Book.query.order_by(Book.date_posted.desc()).limit(5).all()
    return render_template('home.html', listings=listings)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print(f"User found: {user.email}, Password: {user.password}")  # Debugging
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            first_name=html.escape(form.first_name.data),
            last_name=html.escape(form.last_name.data),
            email=html.escape(form.email.data),
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch the user's listings
    listings = Book.query.filter_by(owner=current_user).all()

    # Fetch the user's reservations
    reservations = Reservation.query.filter_by(user_id=current_user.user_id).all()

    # Fetch the user's messages
    received_messages = Message.query.filter_by(recipient_id=current_user.user_id).order_by(Message.timestamp.desc()).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.user_id).order_by(Message.timestamp.desc()).all()

    # Pass the data to the template
    return render_template(
        'dashboard.html',
        listings=listings,
        reservations=reservations,
        received_messages=received_messages,
        sent_messages=sent_messages
    )

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_listing():
    form = CreateListingForm()
    if form.validate_on_submit():
        new_book = Book(
            title=form.title.data,
            author=form.author.data,
            subject=form.subject.data,
            course_code=form.course_code.data,
            condition=form.condition.data,
            availability=form.availability.data,
            user_id=current_user.user_id  # Autofill the owner as the current user
        )
        db.session.add(new_book)
        db.session.commit()
        flash('Your book listing has been created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_listing.html', form=form)

@app.route('/book/<int:book_id>')
@login_required
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)  # Fetch the book by book_id
    reviews = Review.query.filter_by(book_id=book.book_id).all()  # Fetch reviews for the book
    return render_template('book_details.html', book=book, reviews=reviews)

@app.route('/book/<int:book_id>/review', methods=['GET', 'POST'])
@login_required
def add_book_review(book_id):
    book = Book.query.get_or_404(book_id)
    form = ReviewForm()
    if form.validate_on_submit():
        review = Review(
            book_id=book_id,
            reviewer_id=current_user.user_id,
            content=form.content.data,
            rating=int(form.rating.data)
        )
        db.session.add(review)
        db.session.commit()
        flash('Your review has been submitted!', 'success')
        return redirect(url_for('book_detail', book_id=book_id))
    return render_template('add_review.html', form=form, book=book)

@app.route('/edit/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_listing(book_id):
    book = Book.query.get_or_404(book_id)  # Use book_id to fetch the book

    # Ensure the logged-in user owns the listing
    if book.user_id != current_user.user_id:
        flash("You are not authorized to edit this listing.", "danger")
        return redirect(url_for('dashboard'))

    form = BookForm(obj=book)  # Pre-fill the form with the book's details

    if form.validate_on_submit():
        # Update the book's details
        book.title = form.title.data
        book.author = form.author.data
        book.ISBN = form.ISBN.data
        book.subject = form.subject.data
        book.course_code = form.course_code.data
        book.condition = form.condition.data
        book.availability = form.availability.data
        db.session.commit()
        flash("Listing updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_listing.html', form=form, book=book)

@app.route('/books/reserve/<int:book_id>', methods=['POST'])
@login_required
def reserve_book(book_id):
    if not current_user.verified:
        flash('You must verify your account to reserve books.', 'danger')
        return redirect(url_for('verify_account'))

    # Get form data
    due_date = request.form.get('due_date')
    pickup_location = request.form.get('pickup_location')
    reason = request.form.get('reason')

    # Validate the due date
    if not due_date:
        flash('You must select a due date.', 'danger')
        return redirect(url_for('reservations'))

    # Validate pickup location
    if not pickup_location or pickup_location.strip() == "":
        flash('Pickup location cannot be blank.', 'danger')
        return redirect(url_for('reservations'))

    # Check if the book is available
    book = Book.query.get_or_404(book_id)
    if book.availability != 'Available':
        flash('This book is not available for reservation.', 'danger')
        return redirect(url_for('reservations'))

    # Create a reservation
    reservation = Reservation(
        book_id=book.book_id,
        user_id=current_user.user_id,
        date_reserved=datetime.utcnow(),
        due_date=datetime.strptime(due_date, '%Y-%m-%d'),
        pickup_location=pickup_location,
        reason=reason
    )
    book.availability = 'Unavailable'
    db.session.add(reservation)
    db.session.commit()

    # Create a notification for the reservation
    create_notification(
        user_id=current_user.user_id,
        message=f"You have successfully reserved '{book.title}'."
    )

    flash('You have successfully reserved this book.', 'success')
    return redirect(url_for('reservations'))

@app.route('/reservations', methods=['GET'])
@login_required
def reservations():
    # Fetch the user's reservations
    reservations = Reservation.query.filter_by(user_id=current_user.user_id).all()

    # Fetch available books
    available_books = Book.query.filter_by(availability='Available').all()

    # Pass datetime and timedelta to the template
    return render_template(
        'reservations.html',
        reservations=reservations,
        available_books=available_books,
        datetime=datetime,
        timedelta=timedelta
    )

@app.route('/reservations/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)

    # Ensure the reservation belongs to the current user
    if reservation.user_id != current_user.user_id:
        flash('You are not authorized to cancel this reservation.', 'danger')
        return redirect(url_for('reservations'))

    # Update the book's availability
    book = Book.query.get(reservation.book_id)
    book.availability = 'Available'

    # Delete the reservation
    db.session.delete(reservation)
    db.session.commit()

    # Notify the user about the cancellation
    create_notification(
        user_id=current_user.user_id,
        message=f"Your reservation for '{book.title}' has been canceled. The book is now available."
    )

    flash('Your reservation has been canceled.', 'success')
    return redirect(url_for('reservations'))

@app.route('/message_board', methods=['GET', 'POST'])
@login_required
def message_board():
    form = MessageForm()
    parent_id = request.args.get('parent_id')
    parent_message = None

    if parent_id:
        parent_message = Message.query.get_or_404(parent_id)

    if form.validate_on_submit():
        # Create a new message
        message = Message(
            sender_id=current_user.user_id,
            recipient_id=None,  # Set to None for public messages
            topic=form.topic.data if not parent_id else parent_message.topic,
            content=form.content.data,
            link=form.link.data,
            parent_id=parent_id,
        )
        db.session.add(message)
        db.session.commit()
        flash('Message posted successfully!', 'success')
        return redirect(url_for('message_board'))

    # Fetch all messages and eagerly load the sender relationship
    messages = Message.query.options(db.joinedload(Message.sender)).filter_by(parent_id=None).order_by(Message.timestamp.desc()).all()

    return render_template('message_board.html', form=form, messages=messages, parent_message=parent_message)

@app.route('/messages/new/<int:user_id>', methods=['GET', 'POST'])
@login_required
def new_message(user_id):
    recipient = User.query.get_or_404(user_id)
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(
            sender_id=current_user.user_id,
            recipient_id=recipient.user_id,
            topic=form.topic.data,
            content=form.content.data,
            link=form.link.data
        )
        db.session.add(message)
        db.session.commit()
        flash('Your message has been sent.', 'success')
        return redirect(url_for('messages'))
    return render_template('new_message.html', form=form, recipient=recipient)

@app.route('/messages', methods=['GET'])
@login_required
def messages():
    received_messages = Message.query.filter_by(recipient_id=current_user.user_id).order_by(Message.timestamp.desc()).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.user_id).order_by(Message.timestamp.desc()).all()
    return render_template('messages.html', received_messages=received_messages, sent_messages=sent_messages)

@app.route('/messages/reply/<int:message_id>', methods=['GET', 'POST'])
@login_required
def reply_message(message_id):
    parent_message = Message.query.get_or_404(message_id)
    form = MessageForm()
    if form.validate_on_submit():
        reply = Message(
            sender_id=current_user.user_id,
            recipient_id=parent_message.sender_id,
            topic=parent_message.topic,
            content=form.content.data,
            parent_id=parent_message.message_id
        )
        db.session.add(reply)
        db.session.commit()
        flash('Your reply has been sent.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('reply_message.html', form=form, parent_message=parent_message)

@app.route('/search', methods=['GET'])
@login_required
def search_books():
    query = request.args.get('query')
    results = Book.query.filter(
        (Book.title.ilike(f"%{query}%")) |
        (Book.author.ilike(f"%{query}%")) |
        (Book.subject.ilike(f"%{query}%")) |
        (Book.course_code.ilike(f"%{query}%"))
    ).all()
    return render_template('search_results.html', results=results, query=query)

@app.route('/user/<int:user_id>/review', methods=['GET', 'POST'])
@login_required
def add_user_review(user_id):
    user = User.query.get_or_404(user_id)
    form = ReviewForm()
    if form.validate_on_submit():
        review = Review(
            reviewed_user_id=user_id,
            reviewer_id=current_user.user_id,
            content=form.content.data,
            rating=int(form.rating.data)
        )
        db.session.add(review)
        db.session.commit()
        flash('Your review has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_review.html', form=form, user=user)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify_account():
    if current_user.verified:
        flash('Your account is already verified.', 'info')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        email_domain = current_user.email.split('@')[-1]

        # Check if the student ID is valid and email domain ends with .edu
        if student_id and len(student_id) == 8 and email_domain.endswith('.edu'):
            current_user.verified = True
            db.session.commit()
            flash('Your account has been successfully verified!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid student ID or email domain. Please try again.', 'danger')

    return render_template('verify_account.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/notifications/reminders')
def send_return_reminders():
    reservations = Reservation.query.filter(
        Reservation.due_date <= datetime.utcnow() + timedelta(days=2),
        Reservation.due_date > datetime.utcnow()
    ).all()

    for reservation in reservations:
        create_notification(
            user_id=reservation.user_id,
            message=f"Reminder: The book '{reservation.book.title}' is due on {reservation.due_date.strftime('%Y-%m-%d')}."
        )

    flash('Return reminders have been sent.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/notifications/overdue')
def send_overdue_notifications():
    reservations = Reservation.query.filter(
        Reservation.due_date < datetime.utcnow()
    ).all()

    for reservation in reservations:
        create_notification(
            user_id=reservation.user_id,
            message=f"Overdue: The book '{reservation.book.title}' was due on {reservation.due_date.strftime('%Y-%m-%d')}. Please return it as soon as possible."
        )

    flash('Overdue notifications have been sent.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/notifications/mark_as_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_as_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    # Ensure the notification belongs to the current user
    if notification.user_id != current_user.user_id:
        flash('You are not authorized to mark this notification as read.', 'danger')
        return redirect(url_for('dashboard'))

    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('dashboard'))

def create_notification(user_id, message):
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    db.session.commit()

### RUN & INIT ###

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)