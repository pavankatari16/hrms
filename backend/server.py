from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from dotenv import load_dotenv
load_dotenv()
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection

MONGO_URI = os.getenv("MONGO_URI")

client = AsyncIOMotorClient(MONGO_URI)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 8

# Security
security = HTTPBearer()

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ============ MODELS ============

class OrganizationCreate(BaseModel):
    name: str
    admin_name: str
    admin_email: EmailStr
    password: str

class Organization(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    created_at: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    token: str
    user: dict
    organization: dict

class EmployeeCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: Optional[str] = None

class EmployeeUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class Employee(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    org_id: str
    first_name: str
    last_name: str
    email: str
    phone: Optional[str] = None
    created_at: str
    teams: Optional[List[dict]] = []

class TeamCreate(BaseModel):
    name: str
    description: Optional[str] = None

class TeamUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class Team(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    org_id: str
    name: str
    description: Optional[str] = None
    created_at: str
    employee_count: Optional[int] = 0

class TeamAssignment(BaseModel):
    employee_ids: List[str]

class Log(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    org_id: str
    user_id: str
    user_name: str
    action: str
    metadata: dict
    timestamp: str

# ============ HELPER FUNCTIONS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, org_id: str) -> str:
    payload = {
        'user_id': user_id,
        'org_id': org_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user = await db.users.find_one({"id": payload['user_id']})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {**user, 'org_id': payload['org_id']}

async def create_log(org_id: str, user_id: str, user_name: str, action: str, metadata: dict):
    log_entry = {
        "id": str(uuid.uuid4()),
        "org_id": org_id,
        "user_id": user_id,
        "user_name": user_name,
        "action": action,
        "metadata": metadata,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.logs.insert_one(log_entry)

# ============ AUTH ROUTES ============

@api_router.post("/auth/register", response_model=LoginResponse)
async def register_organization(data: OrganizationCreate):
    # Check if email already exists
    existing_user = await db.users.find_one({"email": data.admin_email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create organization
    org_id = str(uuid.uuid4())
    org_doc = {
        "id": org_id,
        "name": data.name,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.organizations.insert_one(org_doc)
    
    # Create admin user
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "org_id": org_id,
        "email": data.admin_email,
        "password_hash": hash_password(data.password),
        "name": data.admin_name,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    # Create log
    await create_log(org_id, user_id, data.admin_name, "organization_created", 
                     {"org_name": data.name})
    
    # Generate token
    token = create_token(user_id, org_id)
    
    return {
        "token": token,
        "user": {"id": user_id, "name": data.admin_name, "email": data.admin_email},
        "organization": {"id": org_id, "name": data.name}
    }

@api_router.post("/auth/login", response_model=LoginResponse)
async def login(data: LoginRequest):
    # Find user
    user = await db.users.find_one({"email": data.email})
    if not user or not verify_password(data.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Get organization
    org = await db.organizations.find_one({"id": user['org_id']})
    
    # Create log
    await create_log(user['org_id'], user['id'], user['name'], "user_login", 
                     {"email": data.email})
    
    # Generate token
    token = create_token(user['id'], user['org_id'])
    
    return {
        "token": token,
        "user": {"id": user['id'], "name": user['name'], "email": user['email']},
        "organization": {"id": org['id'], "name": org['name']}
    }

@api_router.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "user_logout", {})
    return {"message": "Logged out successfully"}

# ============ EMPLOYEE ROUTES ============

@api_router.get("/employees", response_model=List[Employee])
async def get_employees(current_user: dict = Depends(get_current_user)):
    employees = await db.employees.find({"org_id": current_user['org_id']}, {"_id": 0}).to_list(1000)
    
    # Get teams for each employee
    for emp in employees:
        assignments = await db.employee_teams.find({"employee_id": emp['id']}, {"_id": 0}).to_list(100)
        team_ids = [a['team_id'] for a in assignments]
        teams = await db.teams.find({"id": {"$in": team_ids}}, {"_id": 0, "id": 1, "name": 1}).to_list(100)
        emp['teams'] = teams
    
    return employees

@api_router.get("/employees/{employee_id}", response_model=Employee)
async def get_employee(employee_id: str, current_user: dict = Depends(get_current_user)):
    employee = await db.employees.find_one({"id": employee_id, "org_id": current_user['org_id']}, {"_id": 0})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Get teams
    assignments = await db.employee_teams.find({"employee_id": employee_id}, {"_id": 0}).to_list(100)
    team_ids = [a['team_id'] for a in assignments]
    teams = await db.teams.find({"id": {"$in": team_ids}}, {"_id": 0, "id": 1, "name": 1}).to_list(100)
    employee['teams'] = teams
    
    return employee

@api_router.post("/employees", response_model=Employee)
async def create_employee(data: EmployeeCreate, current_user: dict = Depends(get_current_user)):
    employee_id = str(uuid.uuid4())
    employee_doc = {
        "id": employee_id,
        "org_id": current_user['org_id'],
        "first_name": data.first_name,
        "last_name": data.last_name,
        "email": data.email,
        "phone": data.phone,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.employees.insert_one(employee_doc)
    
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "employee_created", {"employee_id": employee_id, "name": f"{data.first_name} {data.last_name}"})
    
    employee_doc['teams'] = []
    return employee_doc

@api_router.put("/employees/{employee_id}", response_model=Employee)
async def update_employee(employee_id: str, data: EmployeeUpdate, current_user: dict = Depends(get_current_user)):
    employee = await db.employees.find_one({"id": employee_id, "org_id": current_user['org_id']})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if update_data:
        await db.employees.update_one({"id": employee_id}, {"$set": update_data})
    
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "employee_updated", {"employee_id": employee_id, "updates": update_data})
    
    updated_employee = await db.employees.find_one({"id": employee_id}, {"_id": 0})
    
    # Get teams
    assignments = await db.employee_teams.find({"employee_id": employee_id}, {"_id": 0}).to_list(100)
    team_ids = [a['team_id'] for a in assignments]
    teams = await db.teams.find({"id": {"$in": team_ids}}, {"_id": 0, "id": 1, "name": 1}).to_list(100)
    updated_employee['teams'] = teams
    
    return updated_employee

@api_router.delete("/employees/{employee_id}")
async def delete_employee(employee_id: str, current_user: dict = Depends(get_current_user)):
    employee = await db.employees.find_one({"id": employee_id, "org_id": current_user['org_id']})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    await db.employees.delete_one({"id": employee_id})
    await db.employee_teams.delete_many({"employee_id": employee_id})
    
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "employee_deleted", {"employee_id": employee_id, "name": f"{employee['first_name']} {employee['last_name']}"})
    
    return {"message": "Employee deleted successfully"}

# ============ TEAM ROUTES ============

@api_router.get("/teams", response_model=List[Team])
async def get_teams(current_user: dict = Depends(get_current_user)):
    teams = await db.teams.find({"org_id": current_user['org_id']}, {"_id": 0}).to_list(1000)
    
    # Get employee count for each team
    for team in teams:
        count = await db.employee_teams.count_documents({"team_id": team['id']})
        team['employee_count'] = count
    
    return teams

@api_router.get("/teams/{team_id}", response_model=Team)
async def get_team(team_id: str, current_user: dict = Depends(get_current_user)):
    team = await db.teams.find_one({"id": team_id, "org_id": current_user['org_id']}, {"_id": 0})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    count = await db.employee_teams.count_documents({"team_id": team_id})
    team['employee_count'] = count
    
    return team

@api_router.post("/teams", response_model=Team)
async def create_team(data: TeamCreate, current_user: dict = Depends(get_current_user)):
    team_id = str(uuid.uuid4())
    team_doc = {
        "id": team_id,
        "org_id": current_user['org_id'],
        "name": data.name,
        "description": data.description,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.teams.insert_one(team_doc)
    
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "team_created", {"team_id": team_id, "name": data.name})
    
    team_doc['employee_count'] = 0
    return team_doc

@api_router.put("/teams/{team_id}", response_model=Team)
async def update_team(team_id: str, data: TeamUpdate, current_user: dict = Depends(get_current_user)):
    team = await db.teams.find_one({"id": team_id, "org_id": current_user['org_id']})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if update_data:
        await db.teams.update_one({"id": team_id}, {"$set": update_data})
    
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "team_updated", {"team_id": team_id, "updates": update_data})
    
    updated_team = await db.teams.find_one({"id": team_id}, {"_id": 0})
    count = await db.employee_teams.count_documents({"team_id": team_id})
    updated_team['employee_count'] = count
    
    return updated_team

@api_router.delete("/teams/{team_id}")
async def delete_team(team_id: str, current_user: dict = Depends(get_current_user)):
    team = await db.teams.find_one({"id": team_id, "org_id": current_user['org_id']})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    await db.teams.delete_one({"id": team_id})
    await db.employee_teams.delete_many({"team_id": team_id})
    
    await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                     "team_deleted", {"team_id": team_id, "name": team['name']})
    
    return {"message": "Team deleted successfully"}

# ============ TEAM ASSIGNMENT ROUTES ============

@api_router.get("/teams/{team_id}/employees")
async def get_team_employees(team_id: str, current_user: dict = Depends(get_current_user)):
    team = await db.teams.find_one({"id": team_id, "org_id": current_user['org_id']})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    assignments = await db.employee_teams.find({"team_id": team_id}, {"_id": 0}).to_list(1000)
    employee_ids = [a['employee_id'] for a in assignments]
    employees = await db.employees.find({"id": {"$in": employee_ids}}, {"_id": 0}).to_list(1000)
    
    return employees

@api_router.post("/teams/{team_id}/assign")
async def assign_employees_to_team(team_id: str, data: TeamAssignment, current_user: dict = Depends(get_current_user)):
    team = await db.teams.find_one({"id": team_id, "org_id": current_user['org_id']})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    for emp_id in data.employee_ids:
        employee = await db.employees.find_one({"id": emp_id, "org_id": current_user['org_id']})
        if not employee:
            continue
        
        # Check if already assigned
        existing = await db.employee_teams.find_one({"employee_id": emp_id, "team_id": team_id})
        if not existing:
            assignment_doc = {
                "id": str(uuid.uuid4()),
                "employee_id": emp_id,
                "team_id": team_id,
                "assigned_at": datetime.now(timezone.utc).isoformat()
            }
            await db.employee_teams.insert_one(assignment_doc)
            
            await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                           "employee_assigned_to_team", 
                           {"employee_id": emp_id, "employee_name": f"{employee['first_name']} {employee['last_name']}", 
                            "team_id": team_id, "team_name": team['name']})
    
    return {"message": "Employees assigned successfully"}

@api_router.post("/teams/{team_id}/unassign")
async def unassign_employees_from_team(team_id: str, data: TeamAssignment, current_user: dict = Depends(get_current_user)):
    team = await db.teams.find_one({"id": team_id, "org_id": current_user['org_id']})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    for emp_id in data.employee_ids:
        employee = await db.employees.find_one({"id": emp_id, "org_id": current_user['org_id']})
        if employee:
            await db.employee_teams.delete_one({"employee_id": emp_id, "team_id": team_id})
            
            await create_log(current_user['org_id'], current_user['id'], current_user['name'], 
                           "employee_unassigned_from_team", 
                           {"employee_id": emp_id, "employee_name": f"{employee['first_name']} {employee['last_name']}", 
                            "team_id": team_id, "team_name": team['name']})
    
    return {"message": "Employees unassigned successfully"}

# ============ LOGS ROUTES ============

@api_router.get("/logs", response_model=List[Log])
async def get_logs(current_user: dict = Depends(get_current_user)):
    logs = await db.logs.find({"org_id": current_user['org_id']}, {"_id": 0}).sort("timestamp", -1).to_list(1000)
    return logs

# ============ MAIN APP ============

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
