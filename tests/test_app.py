import unittest
from app import app, db, User, Book, Reservation, Review, Notification
from flask_login import login_user
from datetime import datetime, timedelta

class TestApp(unittest.TestCase):
    def setUp(self):
        # Configure the app for testing
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.app = app.test_client()
        self.ctx = app.app_context()
        self.ctx.push()
        db.create_all()

        # Create a test user
        self.test_user = User(
            first_name="Test",
            last_name="User",
            email="test@university.edu",
            password="hashed_password",
            verified=True
        )
        db.session.add(self.test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_user_creation(self):
        user = User(
            first_name="John",
            last_name="Doe",
            email="john@university.edu",
            password="hashed_password"
        )
        db.session.add(user)
        db.session.commit()

        self.assertEqual(User.query.count(), 2)  # Including the test user
        self.assertEqual(user.email, "john@university.edu")

    def test_book_creation(self):
        book = Book(
            title="Test Book",
            author="Test Author",
            subject="Math",
            course_code="MATH101",
            condition="New",
            availability="Available",
            user_id=self.test_user.user_id
        )
        db.session.add(book)
        db.session.commit()

        self.assertEqual(Book.query.count(), 1)
        self.assertEqual(book.title, "Test Book")

    def test_reservation_creation(self):
        book = Book(
            title="Test Book",
            author="Test Author",
            subject="Math",
            course_code="MATH101",
            condition="New",
            availability="Available",
            user_id=self.test_user.user_id
        )
        db.session.add(book)
        db.session.commit()

        reservation = Reservation(
            book_id=book.book_id,
            user_id=self.test_user.user_id,
            date_reserved=datetime.utcnow(),
            due_date=datetime.utcnow() + timedelta(days=7),
            pickup_location="Library"
        )
        db.session.add(reservation)
        db.session.commit()

        self.assertEqual(Reservation.query.count(), 1)
        self.assertEqual(reservation.pickup_location, "Library")

    def test_notification_creation(self):
        notification = Notification(
            user_id=self.test_user.user_id,
            message="This is a test notification."
        )
        db.session.add(notification)
        db.session.commit()

        self.assertEqual(Notification.query.count(), 1)
        self.assertEqual(notification.message, "This is a test notification.")

    def test_review_creation(self):
        review = Review(
            book_id=None,
            reviewer_id=self.test_user.user_id,
            reviewed_user_id=self.test_user.user_id,
            content="Great user!",
            rating=5
        )
        db.session.add(review)
        db.session.commit()

        self.assertEqual(Review.query.count(), 1)
        self.assertEqual(review.content, "Great user!")

    def test_user_login(self):
        response = self.app.post('/login', data={
            'email': self.test_user.email,
            'password': 'hashed_password'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)

    def test_create_book_listing(self):
        self.app.post('/login', data={
            'email': self.test_user.email,
            'password': 'hashed_password'
        }, follow_redirects=True)

        response = self.app.post('/create', data={
            'title': 'Integration Test Book',
            'author': 'Integration Author',
            'subject': 'Science',
            'course_code': 'SCI101',
            'condition': 'New',
            'availability': 'Available'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Your book listing has been created!', response.data)
        self.assertEqual(Book.query.count(), 1)

    def test_reserve_book(self):
        # Create a book
        book = Book(
            title="Test Book",
            author="Test Author",
            subject="Math",
            course_code="MATH101",
            condition="New",
            availability="Available",
            user_id=self.test_user.user_id
        )
        db.session.add(book)
        db.session.commit()

        # Log in and reserve the book
        self.app.post('/login', data={
            'email': self.test_user.email,
            'password': 'hashed_password'
        }, follow_redirects=True)

        response = self.app.post(f'/books/reserve/{book.book_id}', data={
            'due_date': (datetime.utcnow() + timedelta(days=7)).strftime('%Y-%m-%d'),
            'pickup_location': 'Library'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'You have successfully reserved this book.', response.data)
        self.assertEqual(Reservation.query.count(), 1)