# SkillSwap

## 📌  Overview
SkillSwap is a peer-to-peer skill exchange platform that enables users to share knowledge and skills without monetary transactions. Users can offer skills they are proficient in (e.g., coding, photography, fitness training) and request skills they want to learn (e.g., language learning, cooking, graphic design). The platform fosters community-driven learning and collaboration.

## 🏗️ Tech Stack
- **Frontend:** HTML, CSS, Bootstrap
- **Backend:** Python / Flask
- **Database:** SQLite with SQLAlchemy
- **Containerization:** Docker
- **Version Control:** Git & GitHub

## 🛠️ How to Set Up the Project
### Prerequisites
- Install [Docker](https://www.docker.com/) and Docker Compose
- Install [Python](https://www.python.org/) 3.9 or later (if running locally)

### Clone the Repository
```sh
$ git clone https://github.com/your-repo/SkillSwap.git
$ cd SkillSwap
```

### Run with Docker (Recommended)
```sh
$ docker-compose up --build
```
This will start the application on http://localhost:5000

### For Local Development (Without Docker)
```sh
$ cd backend
$ pip install -r requirements.txt
$ flask run
```
This will start the development server on http://localhost:5000

### Admin Access
The application creates a default admin user on first run:
- **Username:** admin
- **Password:** admin123

To access the admin portal, log in with these credentials and click on "Admin Portal" in the user dropdown menu.

To create or reset the admin user with custom credentials, use the Flask CLI command:
```sh
$ cd backend
$ flask create-admin --username your_admin --password secure_password --email admin@example.com
```

## 🚀 Project Features
- User authentication (register/login)
- Skill creation and management
- User profiles with offered skills
- Browse available skills by category
- Clean, responsive UI using Bootstrap
- Admin portal for managing users, skills, and verification requests

## 📜 License
This project is licensed under the MIT License.

## 📬 Contact
For inquiries, reach out to any of the team members or create an issue in the GitHub repository.
