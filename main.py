import json
import logging
import os
from datetime import datetime, timedelta
from logging import getLogger
from typing import Dict, List

import bcrypt  # type: ignore
import requests
from db_utils import get_db_connection
from dotenv import load_dotenv  # type: ignore
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse  # type: ignore
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, EmailStr, constr
from request_models import MermaidRequest, RequestModel, UserRequest
from user_session import ChatSession, ChatSessionManager
from typing import List, Optional
import jwt
from fastapi.security import OAuth2PasswordBearer
from test_algorand import router as algorand_router

app = FastAPI()

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "Android@123")  # Ensure you have a strong secret key

# JWT expiration time (in minutes)
JWT_EXPIRATION_TIME = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = getLogger(__name__)
conn = get_db_connection()
PROXY_PREFIX = os.getenv("PROXY_PREFIX", "/api")
app = FastAPI(root_path=PROXY_PREFIX)

API_KEY = os.getenv("API_KEY")


class ModelKWArgs(BaseModel):
    modelParameter: dict = {
        "temperature": 0.75,
        "max_tokens": 2000,
        "top_p": 0.9,
    }


MODEL = os.getenv("MODEL", "anthropic.claude-3-haiku-20240307-v1:0")

origins = [
    "*",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(algorand_router)

# fix the region_name -> us-west-2
session_manager = ChatSessionManager(conn=conn)


MODEL = os.getenv("MODEL", "gemini-1.5-flash")
API_TOKEN = os.environ["API_TOKEN"]

chat_model = ChatGoogleGenerativeAI(
    model=MODEL,
    api_key=API_KEY,
)
# USERS API
class SignInRequest(BaseModel):
    email: str
    password: str

@app.post("/signin")
def sign_in(sign_in_request: SignInRequest):
    email = sign_in_request.email
    password = sign_in_request.password

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT id, email, username, password, birthday, created_at, wallet_name, wallet_address FROM algo_users WHERE email = %s', (email,))
        user_row = cursor.fetchone()

        if not user_row:
            return JSONResponse(status_code=401, content={"statusCode": 401, "body": "Unauthorized"})

        stored_password_hash = user_row[3]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
            return JSONResponse(status_code=401, content={"statusCode": 401, "body": "Unauthorized"})

        # Create JWT token
        payload = {
            "sub": user_row[0],  # User ID
            "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_TIME)  # Expiration time
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        # Fetch user's projects
        cursor.execute('SELECT id, user_id, name, description, fund_id, current_fund, deadline, created_at FROM algo_projects WHERE user_id = %s', (user_row[0],))
        projects = cursor.fetchall()

        project_list = [
            {
                "id": project[0],
                "user_id": project[1],
                "name": project[2],
                "description": project[3],
                "fund_id": project[4],
                "current_fund": project[5],
                "deadline": project[6].strftime('%Y-%m-%d %H:%M:%S'),
                "created_at": project[7].strftime('%Y-%m-%d %H:%M:%S')
            }
            for project in projects
        ]

        cursor.execute('SELECT id, name_fund, members, description, created_at FROM algo_funds WHERE user_id = %s', (user_row[0],))
        funds = cursor.fetchall()

        fund_list = [
            {
                "id": fund[0],
                "name_fund": fund[1],
                "members": fund[2],
                "description": fund[3],
                "created_at": fund[4].strftime('%Y-%m-%d %H:%M:%S')
            }
            for fund in funds
        ]

        user_info = {
            "id": user_row[0],
            "email": user_row[1],
            "name": user_row[2],
            "birthday": user_row[4].strftime('%Y-%m-%d'),
            "created_at": user_row[5].strftime('%Y-%m-%d %H:%M:%S'),
            "wallet_name": user_row[6], 
            "wallet_address": user_row[7], 
            "projects": project_list,
            "funds": fund_list,
            "token": token 
        }

        return JSONResponse(status_code=200, content={"statusCode": 200, "body": user_info})
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()



@app.post("/signout")
def sign_out():
    return JSONResponse(status_code=200, content={"statusCode": 200, "body": "Signed out successfully"})



class RegisterRequest(BaseModel):
    email: str
    name: str
    password: str
    birthday: str #YYYY-MM-DD format


@app.post("/register")
def register(register_request: RegisterRequest):
    email = register_request.email
    name = register_request.name
    password = register_request.password
    birthday = register_request.birthday 

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO algo_users (email, username, password, birthday) 
            VALUES (%s, %s, %s, %s) RETURNING id, email, username, birthday, created_at
        ''', (email, name, hashed_password, birthday))
        
        user = cursor.fetchone()
        conn.commit()

        user_info = {
            "id": user[0],
            "email": user[1],
            "name": user[2],
            "birthday": user[3].strftime('%Y-%m-%d'),  
            "created_at": user[4].strftime('%Y-%m-%d %H:%M:%S') 
        }

        return JSONResponse(status_code=200, content={
            "statusCode": 200, 
            "body": "Registered successfully",
            "user": user_info
        })

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Something went wrong")
    
    finally:
        cursor.close()
        conn.close()

class UpdateUserRequest(BaseModel):
    birthday: Optional[datetime] = None
    wallet_name: Optional[str] = None
    wallet_address: Optional[str] = None
    follow_count: Optional[str] = None
    password: Optional[str] = None


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.put("/user/{user_id}")
def update_user(user_id: int, update_request: UpdateUserRequest, current_user: int = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        update_fields = []
        update_values = []

        if user_id != current_user:
            raise HTTPException(status_code=403, detail="Permission denied: You can only update your own profile.")

        if update_request.birthday is not None:
            update_fields.append("birthday = %s")
            update_values.append(update_request.birthday)

        if update_request.wallet_name is not None:
            update_fields.append("wallet_name = %s")
            update_values.append(update_request.wallet_name)

        if update_request.wallet_address is not None:
            update_fields.append("wallet_address = %s")
            update_values.append(update_request.wallet_address)

        if update_request.follow_count is not None:
            update_fields.append("follow_count = %s")
            update_values.append(update_request.follow_count)

        if update_request.password is not None:
            hashed_password = bcrypt.hashpw(update_request.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            update_fields.append("password = %s")
            update_values.append(hashed_password)

        if not update_fields:
            return JSONResponse(status_code=400, content={"statusCode": 400, "message": "No fields provided to update"})

        update_fields.append("updated_at = NOW()")
        update_values.append(user_id)

        update_query = f"UPDATE algo_users SET {', '.join(update_fields)} WHERE id = %s"

        cursor.execute(update_query, tuple(update_values))
        conn.commit()

        return JSONResponse(status_code=200, content={"statusCode": 200, "message": "User information updated successfully"})
    
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

class UserResponse(BaseModel):
    id: int
    username: Optional[str] = None
    email: Optional[str] = None
    wallet_name: Optional[str] = None
    wallet_address: Optional[str] = None
    birthday: Optional[datetime] = None
    follow_count: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None

@app.get("/user/profile", response_model=UserResponse)
def get_current_user_info(current_user: int = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT id, username, email, birthday, follow_count, created_at, updated_at, deleted_at, wallet_name, wallet_address FROM algo_users WHERE id = %s AND deleted_at IS NULL;', (current_user,))
        user = cursor.fetchone()

        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "id": user[0],
            "username": user[1],  
            "email": user[2],   
            "wallet_name": user[8],
            "wallet_address": user[9],
            "birthday": user[3],
            "follow_count": user[4],
            "created_at": user[5],
            "updated_at": user[6],
            "deleted_at": user[7]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

@app.get("/users", response_model=List[UserResponse])
def get_users(current_user: int = Depends(get_current_user), email: Optional[str] = Query(None)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if email:
            cursor.execute('SELECT id, email, username, birthday, created_at, wallet_name, wallet_address FROM algo_users WHERE email = %s', (email,))
        else:
            cursor.execute('SELECT id, email, username, birthday, created_at, wallet_name, wallet_address FROM algo_users')

        users = cursor.fetchall()

        user_list = [
            {
                "id": user[0],
                "email": user[1],
                "username": user[2],
                "birthday": user[3].strftime('%Y-%m-%d'),
                "created_at": user[4].strftime('%Y-%m-%d %H:%M:%S'),
                "wallet_name": user[5],
                "wallet_address": user[6]
            }
            for user in users
        ]

        return JSONResponse(status_code=200, content={"statusCode": 200, "body": user_list})
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

# FUNDS API
class CreateFundRequest(BaseModel):
    name_fund: str
    user_id: int
    members: List[int]
    description: str
    logo: Optional[str] = None  

@app.post("/funds/create")
def create_fund(create_fund_request: CreateFundRequest, user_id: int = Depends(get_current_user)):
    name_fund = create_fund_request.name_fund
    members = create_fund_request.members
    description = create_fund_request.description
    logo = create_fund_request.logo
    created_at = datetime.utcnow()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO algo_funds (name_fund, user_id, members, description, logo, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (name_fund, user_id, members, description, logo, created_at, created_at))
        conn.commit()

        fund_id = cursor.fetchone()[0]
        return JSONResponse(status_code=200, content={"statusCode": 200, "body": {"fund_id": fund_id}})
    
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

@app.put("/funds/update/{fund_id}")
def update_fund(fund_id: int, update_fund_request: CreateFundRequest, user_id: int = Depends(get_current_user)):
    name_fund = update_fund_request.name_fund
    members = update_fund_request.members
    description = update_fund_request.description
    logo = update_fund_request.logo
    updated_at = datetime.utcnow()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            UPDATE algo_funds
            SET name_fund = %s, members = %s, description = %s, logo = %s, updated_at = %s
            WHERE id = %s
        ''', (name_fund, members, description, logo, updated_at, fund_id))
        conn.commit()

        return JSONResponse(status_code=200, content={"statusCode": 200, "body": "Fund updated successfully"})
    
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

# FIX API
@app.get("/funds/user/{user_id}")
def get_funds_by_user(user_id: int, current_user: int = Depends(get_current_user)):
    if user_id != current_user:
        raise HTTPException(status_code=403, detail="Access forbidden: you do not have permission to access these funds")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Truy vấn để lấy thông tin quỹ và thông tin thành viên
        cursor.execute('''
            SELECT f.id, f.name_fund, f.description, f.logo, f.created_at, 
                   u.id AS user_id, u.name AS user_name
            FROM algo_funds f
            LEFT JOIN algo_users u ON u.id::text = ANY(f.members)
            WHERE f.user_id = %s AND f.deleted_at IS NULL
        ''', (user_id,))
        
        funds = cursor.fetchall()

        # Tạo danh sách quỹ và thông tin thành viên
        funds_list = []
        for fund in funds:
            fund_id = fund[0]
            # Kiểm tra xem quỹ đã có trong danh sách chưa
            fund_info = next((f for f in funds_list if f["id"] == fund_id), None)
            if not fund_info:
                fund_info = {
                    "id": fund_id,
                    "name_fund": fund[1],
                    "description": fund[2],
                    "logo": fund[3],
                    "created_at": fund[4].strftime('%Y-%m-%d %H:%M:%S'),
                    "members": []  # Khởi tạo danh sách thành viên
                }
                funds_list.append(fund_info)
            
            # Thêm thông tin thành viên vào quỹ
            if fund[5] is not None:  # Kiểm tra nếu user_id không phải là NULL
                fund_info["members"].append({
                    "user_id": fund[5],
                    "name": fund[6]
                })

        return JSONResponse(status_code=200, content={"statusCode": 200, "body": funds_list})
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

@app.get("/funds/{fund_id}/user/{user_id}")
def get_one_fund_by_user(fund_id: int, user_id: int, current_user: int = Depends(get_current_user)):
    if user_id != current_user:
        raise HTTPException(status_code=403, detail="Access forbidden: you do not have permission to access these funds")

    conn = get_db_connection()
    cursor = conn.cursor()
   
    try:
        cursor.execute('SELECT id, name_fund, members, description, logo, created_at FROM algo_funds WHERE user_id = %s AND id = %s AND deleted_at IS NULL', (user_id, fund_id,))
        fund = cursor.fetchone()
        if not fund:
            raise HTTPException(status_code=404, detail="Fund not found")

        fund_info = {
            "id": fund[0],
            "name_fund": fund[1],
            "members": fund[2],
            "description": fund[3],
            "logo": fund[4],
            "created_at": fund[5].strftime('%Y-%m-%d %H:%M:%S')
        }

        return JSONResponse(status_code=200, content={"statusCode": 200, "body": fund_info })
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()


#PROJECT APIS
class CreateProjectRequest(BaseModel):
    user_id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None
    fund_id: Optional[int] = None
    current_fund: Optional[int] = None
    fund_raise_total: Optional[int] = None
    fund_raise_count: Optional[int] = None
    deadline: Optional[datetime] = None
    project_hash: Optional[str] = None 
    is_verify: Optional[bool] = None
    status: Optional[str] = None
    linkcardImage: Optional[List[str]] = None
    type: Optional[str] = None  

class ProjectResponse(BaseModel):
    id: Optional[int] = None
    user_id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None
    fund_id: Optional[int] = None
    current_fund: Optional[int] = None
    fund_raise_total: Optional[int] = None
    fund_raise_count: Optional[int] = None
    deadline: Optional[datetime] = None
    project_hash: Optional[str] = None
    is_verify: Optional[bool] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None
    linkcardImage: Optional[List[str]] = None 
    type: Optional[str] = None

@app.post("/projects", response_model=ProjectResponse)
def create_project(project_request: CreateProjectRequest, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    created_at = datetime.now()
    updated_at = created_at

    try:
        cursor.execute('''
            INSERT INTO algo_projects (user_id, name, description, fund_id, current_fund, fund_raise_total, fund_raise_count, 
            deadline, project_hash, is_verify, status, linkcardImage, type, created_at, updated_at) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
        ''', (
            project_request.user_id, 
            project_request.name, 
            project_request.description, 
            project_request.fund_id, 
            project_request.current_fund, 
            project_request.fund_raise_total, 
            project_request.fund_raise_count, 
            project_request.deadline, 
            project_request.project_hash, 
            project_request.is_verify, 
            project_request.status,
            project_request.linkcardImage, 
            project_request.type,  
            created_at, 
            updated_at
        ))

        project_id = cursor.fetchone()[0]
        conn.commit()

        return {
            "id": project_id,
            "user_id": project_request.user_id,
            "name": project_request.name,
            "description": project_request.description,
            "fund_id": project_request.fund_id,
            "current_fund": project_request.current_fund,
            "fund_raise_total": project_request.fund_raise_total,
            "fund_raise_count": project_request.fund_raise_count,
            "deadline": project_request.deadline,
            "project_hash": project_request.project_hash,
            "is_verify": project_request.is_verify,
            "status": project_request.status,
            "linkcardImage": project_request.linkcardImage,  
            "type": project_request.type, 
            "created_at": created_at,
            "updated_at": updated_at
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

class Contribution(BaseModel):
    project_id: int
    txid: str # ma giao dich
    amount: float
    email: Optional[str] = None
    sodienthoai: Optional[str] = None
    address: Optional[str] = None
    name: Optional[str] = None
    type_sender_wallet: str
    sender_wallet_address: str
    receiver_wallet_addres: str
    time_round: datetime  

# Pydantic model for the contribution response
class ContributionResponse(BaseModel):
    project_id: int
    txid: str
    amount: float
    email: str
    sodienthoai: str
    address: str
    name: str
    type_sender_wallet: str
    sender_wallet_address: str
    receiver_wallet_addres: str
    time_round: datetime  
    project_current_fund: float
    fund_raise_count: int

@app.post("/projects/{project_id}/contributions", response_model=ContributionResponse)
def insert_contribution(
    project_id: int,
    contribution: Contribution,
    x_key_sc: str = Depends(lambda: os.getenv('x_key_sc'))
):
    if x_key_sc != os.getenv('x_key_sc'):
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO algo_contributions (project_id, txid, amount, email, sodienthoai, address, name, type_sender_wallet, sender_wallet_address, receiver_wallet_addres, time_round)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;  -- Return the new contribution ID
        ''', (project_id, contribution.txid, contribution.amount, contribution.email, contribution.sodienthoai, contribution.address, contribution.name, contribution.type_sender_wallet, contribution.sender_wallet_address, contribution.receiver_wallet_addres, contribution.time_round))

        contribution_id = cursor.fetchone()[0]

    # Update the current_fund of the corresponding project in algo_projects table
        cursor.execute('''
            UPDATE algo_projects
            SET current_fund = current_fund + %s
                fund_raise_count = fund_raise_count + 1
            WHERE id = %s;
        ''', (contribution.amount, project_id))

        updated_fund, updated_raise_count = cursor.fetchone()
        conn.commit()
        
        response_ = {
            "contribution_id": contribution_id,
            "project_id": project_id,
            "txid": contribution.txid,
            "amount": contribution.amount,
            "email": contribution.email,
            "sodienthoai": contribution.sodienthoai,
            "address": contribution.address,
            "name": contribution.name,
            "type_sender_wallet": contribution.type_sender_wallet,
            "sender_wallet_address": contribution.sender_wallet_address,
            "receiver_wallet_addres": contribution.receiver_wallet_addres,
            "time_round" : contribution.time_round,
            "current_fund": updated_fund,
            "fund_raise_count": updated_raise_count
        }
        return JSONResponse(status_code=200, content={"statusCode": 200, "body": response_})
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.put("/projects/{project_id}", response_model=ProjectResponse)
def update_project(project_id: int, project_request: CreateProjectRequest, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    updated_at = datetime.now()

    try:
        cursor.execute('SELECT * FROM algo_projects WHERE id = %s', (project_id,))
        current_project = cursor.fetchone()

        if not current_project:
            raise HTTPException(status_code=404, detail="Project not found.")

        updated_fields = {
            "user_id": project_request.user_id if project_request.user_id is not None else current_project[1],
            "name": project_request.name if project_request.name is not None else current_project[2],
            "description": project_request.description if project_request.description is not None else current_project[3],
            "fund_id": project_request.fund_id if project_request.fund_id is not None else current_project[4],
            "current_fund": project_request.current_fund if project_request.current_fund is not None else current_project[5],
            "fund_raise_total": project_request.fund_raise_total if project_request.fund_raise_total is not None else current_project[6],
            "fund_raise_count": project_request.fund_raise_count if project_request.fund_raise_count is not None else current_project[7],
            "deadline": project_request.deadline if project_request.deadline is not None else current_project[8],
            "project_hash": project_request.project_hash if project_request.project_hash is not None else current_project[9],
            "is_verify": project_request.is_verify if project_request.is_verify is not None else current_project[10],
            "status": project_request.status if project_request.status is not None else current_project[11],
            "linkcardImage": project_request.linkcardImage if project_request.linkcardImage is not None else current_project[12], 
            "type": project_request.type if project_request.type is not None else current_project[13],  
        }

        cursor.execute('''
            UPDATE algo_projects 
            SET user_id = %s, name = %s, description = %s, fund_id = %s, current_fund = %s, 
                fund_raise_total = %s, fund_raise_count = %s, deadline = %s, 
                project_hash = %s, is_verify = %s, status = %s, linkcardImage = %s, type = %s, updated_at = %s 
            WHERE id = %s;
        ''', (
            updated_fields["user_id"],
            updated_fields["name"],
            updated_fields["description"],
            updated_fields["fund_id"],
            updated_fields["current_fund"],
            updated_fields["fund_raise_total"],
            updated_fields["fund_raise_count"],
            updated_fields["deadline"],
            updated_fields["project_hash"],
            updated_fields["is_verify"],
            updated_fields["status"],
            updated_fields["linkcardImage"],
            updated_fields["type"],  
            updated_at,
            project_id
        ))

        conn.commit()

        return {
            "id": project_id,
            "user_id": updated_fields["user_id"],
            "name": updated_fields["name"],
            "description": updated_fields["description"],
            "fund_id": updated_fields["fund_id"],
            "current_fund": updated_fields["current_fund"],
            "fund_raise_total": updated_fields["fund_raise_total"],
            "fund_raise_count": updated_fields["fund_raise_count"],
            "deadline": updated_fields["deadline"],
            "project_hash": updated_fields["project_hash"],
            "is_verify": updated_fields["is_verify"],
            "status": updated_fields["status"],
            "linkcardImage": updated_fields["linkcardImage"],  
            "type": updated_fields["type"],  
            "created_at": current_project[14], 
            "updated_at": updated_at
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()
      

@app.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT p.*, f.name_fund, f.logo, f.description 
            FROM algo_projects p
            LEFT JOIN algo_funds f ON p.fund_id = f.id
            WHERE p.id = %s AND p.deleted_at IS NULL;
        ''', (project_id,))
        project = cursor.fetchone()

        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        project_data = {
            "id": project[0],
            "user_id": project[1],
            "name": project[2],
            "description": project[3],
            "fund_id": project[4],
            "current_fund": project[5],
            "fund_raise_total": project[6],
            "fund_raise_count": project[7],
            "deadline": project[8].strftime('%Y-%m-%d %H:%M:%S') if project[8] else None,
            "project_hash": project[9],
            "is_verify": project[10],
            "status": project[11],
            "linkcardImage": project[15],
            "type": project[16],
            "created_at": project[12].strftime('%Y-%m-%d %H:%M:%S') if project[12] else None,
            "updated_at": project[13].strftime('%Y-%m-%d %H:%M:%S') if project[13] else None,
            "deleted_at": project[14].strftime('%Y-%m-%d %H:%M:%S') if project[14] else None,
            "fund_name": project[17],
            "fund_logo": project[18],
            "fund_description": project[19]
        }
        return JSONResponse(status_code=200, content={"statusCode": 200, "body": project_data})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/projects", response_model=List[ProjectResponse])
def get_projects():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT p.*, f.name_fund, f.logo, f.description 
            FROM algo_projects p
            LEFT JOIN algo_funds f ON p.fund_id = f.id
            WHERE p.deleted_at IS NULL
            ORDER BY p.id DESC;
        ''')
        projects = cursor.fetchall()

        project_list = [{
            "id": project[0],
            "user_id": project[1],
            "name": project[2],
            "description": project[3],
            "fund_id": project[4],
            "current_fund": project[5],
            "fund_raise_total": project[6],
            "fund_raise_count": project[7],
            "deadline": project[8].strftime('%Y-%m-%d %H:%M:%S') if project[8] else None,
            "project_hash": project[9],
            "is_verify": project[10],
            "status": project[11],
            "linkcardImage": project[15], 
            "type": project[16], 
            "created_at": project[12].strftime('%Y-%m-%d %H:%M:%S') if project[12] else None,
            "updated_at": project[13].strftime('%Y-%m-%d %H:%M:%S') if project[13] else None,
            "deleted_at": project[14].strftime('%Y-%m-%d %H:%M:%S') if project[14] else None,
            "fund_name": project[17],
            "fund_logo": project[18],
            "fund_description": project[19]
        } for project in projects]
        return JSONResponse(status_code=200, content={"statusCode": 200, "body": project_list})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/projects/filter/user/{user_id}/fund/{fund_id}", response_model=List[ProjectResponse])
def filter_projects(
    user_id: int,
    fund_id: int,
    current_user: dict = Depends(get_current_user)
):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        query = '''
            SELECT p.*, f.name_fund, f.logo, f.description 
            FROM algo_projects p
            LEFT JOIN algo_funds f ON p.fund_id = f.id
            WHERE p.deleted_at IS NULL
            AND p.user_id = %s
            AND p.fund_id = %s
            ORDER BY p.id DESC;
        '''

        cursor.execute(query, (user_id, fund_id))
        projects = cursor.fetchall()

        project_list = [{
            "id": project[0],
            "user_id": project[1],
            "name": project[2],
            "description": project[3],
            "fund_id": project[4],
            "current_fund": project[5],
            "fund_raise_total": project[6],
            "fund_raise_count": project[7],
            "deadline": project[8].strftime('%Y-%m-%d %H:%M:%S') if project[8] else None,
            "project_hash": project[9],
            "is_verify": project[10],
            "status": project[11],
            "linkcardImage": project[15], 
            "type": project[16], 
            "created_at": project[12].strftime('%Y-%m-%d %H:%M:%S') if project[12] else None,
            "updated_at": project[13].strftime('%Y-%m-%d %H:%M:%S') if project[13] else None,
            "deleted_at": project[14].strftime('%Y-%m-%d %H:%M:%S') if project[14] else None,
            "fund_name": project[17],
            "fund_logo": project[18],
            "fund_description": project[19]
        } for project in projects]
        
        return JSONResponse(status_code=200, content={"statusCode": 200, "body": project_list})
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

@app.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            UPDATE algo_projects 
            SET deleted_at = %s 
            WHERE id = %s;
        ''', (datetime.now(), project_id))
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Project not found")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

class UpdateProjectFundingRequest(BaseModel):
    current_fund: float
    email: EmailStr | None = None
    sodienthoai: constr(max_length=50) | None = None  # type: ignore # Optional phone number
    address: str | None = None 
    name: str | None = None  
    type_sender_wallet: str | None = None
    sender_wallet_address: str | None = None  


@app.put("/projects/{project_id}/addFund", response_model=ProjectResponse)
def update_project_funding(project_id: int, funding_request: UpdateProjectFundingRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    updated_at = datetime.now()

    try:
        cursor.execute('SELECT * FROM algo_projects WHERE id = %s', (project_id,))
        current_project = cursor.fetchone()

        if not current_project:
            raise HTTPException(status_code=404, detail="Project not found.")

        current_fund = current_project[5]  
        fund_raise_total = current_project[6] 
        fund_raise_count = current_project[7] 

        new_current_fund = current_fund + funding_request.current_fund
        if new_current_fund > fund_raise_total:
            raise HTTPException(status_code=400, detail="Current fund exceeds the total fundraising goal.")

        cursor.execute('''
            UPDATE algo_projects 
            SET current_fund = %s, fund_raise_count = fund_raise_count + 1, updated_at = %s 
            WHERE id = %s;
        ''', (
            new_current_fund,
            updated_at,
            project_id
        ))

        cursor.execute('''
            INSERT INTO algo_s (project_id, amount, email, sodienthoai, address, name, type_sender_wallet, sender_wallet_address, created_at, updated_at) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        ''', (
            project_id,
            funding_request.current_fund,
            funding_request.email if funding_request.email else None,
            funding_request.sodienthoai if funding_request.sodienthoai else None,
            funding_request.address if funding_request.address else None,
            funding_request.name if funding_request.name else None,
            funding_request.type_sender_wallet,
            funding_request.sender_wallet_address,
            updated_at,
            updated_at
        ))

        conn.commit()

        return {
            "id": project_id,
            "user_id": current_project[1],
            "name": current_project[2],
            "description": current_project[3],
            "fund_id": current_project[4],
            "current_fund": new_current_fund,
            "fund_raise_total": fund_raise_total,
            "fund_raise_count": fund_raise_count + 1,
            "deadline": current_project[8],
            "project_hash": current_project[9],
            "is_verify": current_project[10],
            "status": current_project[11],
            "created_at": current_project[12],
            "updated_at": updated_at
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

class Response(BaseModel):
    id: int
    project_id: int
    amount: Optional[float] = None
    email: Optional[str] = None
    sodienthoai: Optional[str] = None
    address: Optional[str] = None
    name: Optional[str] = None
    type_sender_wallet: Optional[str] = None
    sender_wallet_address: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@app.get("/projects/{project_id}/contributions", response_model=List[ContributionResponse])
def get_contributions_by_project_id(project_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT id, project_id, amount, email, sodienthoai, address, name,
                   type_sender_wallet, sender_wallet_address, created_at, updated_at
            FROM algo_contributions
            WHERE project_id = %s;
        ''', (project_id,))

        contributions = cursor.fetchall()

        if not contributions:
            raise HTTPException(status_code=404, detail="No contributions found for this project.")

        response = [
            contrib.dict()
            for contrib in [
                ContributionResponse(
                    id=contrib[0],
                    project_id=contrib[1],
                    amount=contrib[2],
                    email=contrib[3],
                    sodienthoai=contrib[4],
                    address=contrib[5],
                    name=contrib[6],
                    type_sender_wallet=contrib[7],
                    sender_wallet_address=contrib[8],
                    created_at=contrib[9].isoformat() if contrib[9] else None,
                    updated_at=contrib[10].isoformat() if contrib[10] else None     
                )
                for contrib in contributions
            ]
        ]
        return JSONResponse(status_code=200, content={"statusCode": 200, "body": response})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# RECEIVERS API

class ReceiverBase(BaseModel):
    project_id: int
    email: Optional[EmailStr] = None
    sodienthoai: Optional[str] = None
    address: Optional[str] = None
    name: Optional[str] = None
    type_receiver_wallet: Optional[str] = None
    receiver_wallet_address: Optional[str] = None

class ReceiverCreate(ReceiverBase):
    pass

class ReceiverUpdate(ReceiverBase):
    pass

class ReceiverResponse(BaseModel):
    id: int
    project_id: int
    email: Optional[str] = None
    sodienthoai: Optional[str] = None
    address: Optional[str] = None
    name: Optional[str] = None
    type_receiver_wallet: Optional[str] = None
    receiver_wallet_address: Optional[str] = None
    created_at: str 
    updated_at: str 

@app.get("/receivers", response_model=List[ReceiverResponse])
def get_receivers(email: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        query = "SELECT * FROM algo_receivers"
        params = []

        if email:
            query += " WHERE email = %s"
            params.append(email)

        cursor.execute(query, params)
        receivers = cursor.fetchall()
        
        response = [
            {
                "id": receiver[0],
                "project_id": receiver[1],
                "email": receiver[2],
                "sodienthoai": receiver[3],
                "address": receiver[4],
                "name": receiver[5],
                "type_receiver_wallet": receiver[6],
                "receiver_wallet_address": receiver[7],
                "created_at": receiver[8].isoformat() if receiver[8] else None,  
                "updated_at": receiver[9].isoformat() if receiver[9] else None 
            }
            for receiver in receivers
        ]

        return JSONResponse(status_code=200, content=response)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()


@app.post("/receivers", response_model=ReceiverResponse, status_code=status.HTTP_201_CREATED)
def create_receiver(receiver: ReceiverCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    created_at = datetime.now()
    updated_at = created_at

    try:
        cursor.execute('''
            SELECT id FROM algo_projects WHERE id = %s;
        ''', (receiver.project_id,))
        project = cursor.fetchone()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found.")

        cursor.execute('''
            INSERT INTO algo_receivers (project_id, email, sodienthoai, address, name, 
                                         type_receiver_wallet, receiver_wallet_address, created_at, updated_at) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
        ''', (
            receiver.project_id,
            receiver.email,
            receiver.sodienthoai,
            receiver.address,
            receiver.name,
            receiver.type_receiver_wallet,
            receiver.receiver_wallet_address,
            created_at,
            updated_at
        ))

        receiver_id = cursor.fetchone()[0]
        conn.commit()

        return {**receiver.dict(), "id": receiver_id, "created_at": created_at.isoformat(), "updated_at": updated_at.isoformat()}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()


@app.put("/receivers/{receiver_id}", response_model=ReceiverResponse)
def update_receiver(receiver_id: int, receiver: ReceiverCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    updated_at = datetime.now()

    try:
        cursor.execute("SELECT * FROM algo_receivers WHERE id = %s", (receiver_id,))
        existing_receiver = cursor.fetchone()

        if not existing_receiver:
            raise HTTPException(status_code=404, detail="Receiver not found.")

        cursor.execute('''
            UPDATE algo_receivers 
            SET project_id = %s, email = %s, sodienthoai = %s, address = %s, 
                name = %s, type_receiver_wallet = %s, receiver_wallet_address = %s, 
                updated_at = %s 
            WHERE id = %s;
        ''', (
            receiver.project_id,
            receiver.email,
            receiver.sodienthoai,
            receiver.address,
            receiver.name,
            receiver.type_receiver_wallet,
            receiver.receiver_wallet_address,
            updated_at,
            receiver_id
        ))

        conn.commit()

        updated_receiver = {
            "id": receiver_id,
            "project_id": receiver.project_id,
            "email": receiver.email,
            "sodienthoai": receiver.sodienthoai,
            "address": receiver.address,
            "name": receiver.name,
            "type_receiver_wallet": receiver.type_receiver_wallet,
            "receiver_wallet_address": receiver.receiver_wallet_address,
            "created_at": existing_receiver[8].isoformat() if existing_receiver[8] else None,
            "updated_at": updated_at.isoformat() 
        }

        return JSONResponse(status_code=status.HTTP_200_OK, content=updated_receiver)

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

@app.delete("/receivers/{receiver_id}", status_code=status.HTTP_200_OK)
def delete_receiver(receiver_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM algo_receivers WHERE id = %s', (receiver_id,))
        existing_receiver = cursor.fetchone()

        if not existing_receiver:
            raise HTTPException(status_code=404, detail="Receiver not found.")

        cursor.execute('DELETE FROM algo_receivers WHERE id = %s', (receiver_id,))
        conn.commit()

        return JSONResponse(status_code=status.HTTP_200_OK, content={"statusCode": 200, "detail": "Receiver deleted successfully."})
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        cursor.close()
        conn.close()

class Receiver(BaseModel):
    id: int
    project_id: int
    email: str | None = None
    sodienthoai: str | None = None
    address: str | None = None
    name: str | None = None
    type_receiver_wallet: str | None = None
    receiver_wallet_address: str | None = None

class TransactionResponse(BaseModel):
    receiver_id: int
    project_id: int
    transaction_count: int
    amount: float
    time_round: str
    created_at: str
    updated_at: str

@app.post("/projects/{project_id}/distribute_fund", response_model=List[TransactionResponse])
def distribute_funds(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT current_fund, fund_raise_total FROM algo_projects WHERE id = %s;
        ''', (project_id,))
        project = cursor.fetchone()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found.")

        current_fund, fund_raise_total = project
        if current_fund != fund_raise_total:
            raise HTTPException(status_code=400, detail="Current fund does not equal fund raise total.")

        cursor.execute('SELECT * FROM algo_receivers WHERE project_id = %s;', (project_id,))
        receivers = cursor.fetchall()

        if not receivers:
            raise HTTPException(status_code=404, detail="No receivers found for this project.")

        num_receivers = len(receivers)
        amount_per_receiver = current_fund / num_receivers

        transactions = []
        for i, receiver in enumerate(receivers):
            receiver_id = receiver[0]
            cursor.execute('''
                INSERT INTO algo_receivers_transaction (receiver_id, project_id, transaction_count, amount, time_round, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
            ''', (
                receiver_id,
                project_id,
                i + 1, 
                amount_per_receiver,
                datetime.now(), 
                datetime.now(),
                datetime.now() 
            ))
            transaction_id = cursor.fetchone()[0]
            transactions.append({
                "receiver_id": receiver_id,
                "project_id": project_id,
                "transaction_count": i + 1,
                "amount": amount_per_receiver,
                "time_round": datetime.now().isoformat(),
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            })

        conn.commit()
        return transactions

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

    finally:
        cursor.close()
        conn.close()

@app.get("/health-check")
def health_check():
    return {"status": "ok"}


@app.get("/")
def home():
    return {"message": "Solar Sailors welcome you to the backend of the project."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
