Human Resource Management System (HRMS)

A full-stack HRMS system built with a backend API and a React-based frontend.

Features

Organization registration & login (JWT-based)

Employee CRUD (create, update, delete)

Team CRUD

Assign employees to multiple teams

Complete activity logging (login, CRUD, team assignment)

Secure role-based access

Organization-level data isolation

Tech Stack

Backend: FastAPI (Python)

Frontend: React + Vite

Database: MongoDB (Atlas)

Auth: JWT + bcrypt

How to Run

Backend

cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --reload


Frontend

cd frontend
npm install
npm run dev

Deployment

Frontend: Vercel

Backend: Render / Railway
