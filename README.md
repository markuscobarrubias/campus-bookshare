# Campus BookShare

Campus BookShare is a web application designed to facilitate book exchanges among university students. Users can list books for sharing, reserve books, leave reviews, and communicate with other users through a messaging system. The platform also includes features like user verification, notifications, and a search functionality to enhance security and usability.

---

## Features

- **User Registration and Login**: Secure user authentication with email and password.
- **User Verification**: Accounts are verified using `.edu` email addresses and student IDs.
- **Book Listings**: Users can create, edit, and manage book listings.
- **Reservations**: Reserve books and manage reservations.
- **Messaging System**: Communicate with other users via private messages and a public message board.
- **Reviews**: Leave reviews for books and users, with reputation scores displayed on user profiles.
- **Notifications**: Automated notifications for reservation confirmations, return reminders, overdue books, and availability updates.
- **Search Functionality**: Search for books by title, author, subject, or course code.

---

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- Virtual environment (optional but recommended)
- SQLite (default database)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/campus-bookshare.git
   cd campus-bookshare
   
2.  **Set Up a Virtual Environment**
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install Dependencies**
   pip install -r requirements.txt

4. **Set Up the Database. Initialize the SQLite database:**
    flask db upgrade

5. **Run the Application. Start the Flask development server:**
    flask run

6. **Access the Application**
    http://127.0.0.1:5000

Usage
User Registration and Verification
Register with a .edu email address.
Verify your account by providing an 8-digit student ID.
Book Listings
Create a new book listing from the dashboard.
Edit or delete your listings as needed.
Reservations
Reserve available books and manage your reservations.
Cancel reservations if needed.
Messaging
Send private messages to other users.
Participate in public discussions on the message board.
Reviews
Leave reviews for books and users.
View reputation scores on user profiles.
Notifications
Receive notifications for reservation confirmations, return reminders, overdue books, and availability updates.
Testing
Unit Tests
Run unit tests to verify backend logic:
    python -m unittest [test_app.py](http://_vscodecontentref_/0)
Integration Tests
Run integration tests to simulate user behavior:
    pytest [test_app.py](http://_vscodecontentref_/1)


Campus BookShare/
│
├── [app.py](http://_vscodecontentref_/2)                 # Main application file
├── [requirements.txt](http://_vscodecontentref_/3)       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html          # Base template
│   ├── dashboard.html     # Dashboard page
│   ├── register.html      # Registration page
│   ├── login.html         # Login page
│   ├── verify_account.html # Account verification page
│   ├── book_details.html  # Book details page
│   ├── add_review.html    # Add review page
│   └── ...                # Other templates
├── static/                # Static files (CSS, JS, images)
│   ├── styles.css         # Main stylesheet
│   └── uploads/           # Uploaded files
├── migrations/            # Database migrations
├── [test_app.py](http://_vscodecontentref_/4)            # Unit and integration tests
└── README.md              # Project documentation

Technologies Used
Backend: Flask, Flask-SQLAlchemy, Flask-WTF, Flask-Login
Frontend: HTML, CSS, Bootstrap
Database: SQLite (default)