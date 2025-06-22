from fastapi import FastAPI, HTTPException, Depends
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, text
from sqlalchemy.orm import sessionmaker
from argon2 import PasswordHasher
from databases import Database
from datetime import timedelta
import jwt
# Database setup
DATABASE_URL = "mysql+pymysql://root:root123@localhost/login"
database = Database(DATABASE_URL)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
metadata = MetaData()
access_token = None
hashed_password =None
authjwt_secret_key = None
# MySQL table definition
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(50)),
    Column("office", String(100)),
    Column("hire_date", String(100)),
    Column("address", String(255)),
    Column("email", String(255), unique=True),
    Column("password", String(200)),
)
todo = Table(
    "todo",
    metadata,
    Column("id_todo",Integer,primary_key=True),
    Column("tasks", String(500)),
)
roles = Table(
    "roles",
    metadata,
    Column("r_id", Integer, primary_key=True),
    Column("role_name", String(50), unique=True),
)
departments = Table(
    "departments",
    metadata,
    Column("D_id", Integer, primary_key=True),
    Column("department_name", String(100)),
)
projects = Table(
    "projects",
    metadata,
    Column("P_id", Integer, primary_key=True),
    Column("project_name", String(100)),
    Column("description", String(255)),
)
messages = Table(
    "messages",
    metadata,
    Column("M_id", Integer, primary_key=True),
    Column("sender_id", Integer),
    Column("receiver_id", Integer),
    Column("message", String(500)),
)
feedback = Table(
    "feedback",
    metadata,
    Column("F_id", Integer, primary_key=True),
    Column("user_id", Integer),
    Column("comment", String(255)),
    Column("rating", Integer)  # e.g., 1 to 5
)


metadata.create_all(engine)
ph = PasswordHasher() # hashing lib object
# Hashing password
class todo(BaseModel):
    tasks : str
class User(BaseModel):
    name: str
    office: str
    hire_date: str
    address: str
    email: str
    password: str

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_access_token_expires: timedelta = timedelta(minutes=5)
class UserLogin(BaseModel):
    email: str
    password: str 
class Role(BaseModel):
    role_name: str
    model_config = {"from_attributes": True}
class Department(BaseModel):
    department_name: str
    model_config = {"from_attributes": True}
class Project(BaseModel):
    project_name: str
    description: str
    model_config = {"from_attributes": True}
class Message(BaseModel):
    sender_id: int
    receiver_id: int
    message: str

    model_config = {"from_attributes": True}


class Feedback(BaseModel):
    user_id: int
    comment: str
    rating: int
app = FastAPI()
@app.on_event("startup")
async def startup():
    await database.connect()
@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
# Authentication
@AuthJWT.load_config
def get_config():
    return Settings()
def hash_password(password: str) -> str:
    return ph.hash(password)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# Dependency to get DB session
# Register route
@app.post("/register")
async def register(user: User, database: SessionLocal = Depends(get_db)):
    hashed_password = hash_password(user.password)
    # Check if user already exists
    query = text(f"SELECT * FROM users WHERE email = '{user.email}'")
    existing_user = database.execute(query, {"email": user.email}).fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    #Insert the new user
    insert_query = text(f"""
        INSERT INTO users (name, office, hire_date, address, email, password)
        VALUES ('{user.name}', '{user.office}', '{user.hire_date}', '{user.address}', '{user.email}','{hashed_password}')
    """)
    database.execute(insert_query, {
        "name": user.name,
        "office": user.office,
        "hire_date": user.hire_date,
        "address": user.address,
        "email": user.email,
        "password": hashed_password    
    })
    database.commit()
    raise HTTPException(status_code=200, detail="User registered successfully") 
@app.post("/login")
async def login(User: UserLogin, Authorize: AuthJWT = Depends()):
    global access_token
    try:
        query = f"SELECT password FROM users where email = '{User.email}'"
        passw = await database.fetch_one(query)
        correct = ph.verify(passw.password, User.password)
        if correct:
            try:
                queryy = text(f"SELECT email FROM users WHERE email = '{User.email}'")
                result = await database.fetch_one(queryy)
                access_token = Authorize.create_access_token(subject=str(result.email))
                return access_token
            except Exception as e:
                print(f"Error during token creation: {str(e)}")
                return "Error during token creation"
        else:
            return "invalid hash error"
    
    except Exception as e:
        print(f"Password verification failed: {str(e)}")
        return "email or password is incorrect "
# Secure routes with JWT
@app.get("/me")
async def me(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])
    query = (f"Select name ,email,password, office, hire_date From users where email = '{decoded_token.get("sub")}'")
    return await database.fetch_one(query) , decoded_token 
@app.get("/users/")
async def read_users(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    query = text("SELECT name , office, email, hire_date,address FROM users")
    result = await database.fetch_all(query)
    return result
@app.get("/users/{name}")
async def get_user_by_name(name: str, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        query = text(f"SELECT name, office, hire_date, address, email FROM users WHERE name LIKE '{name}%'")
        result = await database.fetch_one(query)
        if result is None:
            raise HTTPException(status_code=404, detail="user not found")
        return result
    except Exception as e:
        raise HTTPException(status_code=404, detail="user not found") from e

@app.delete("/delete/")
async def delete_user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])
    try:    
        email =  decoded_token.get("sub")
        query2 = (f"Select id from users where email = '{email}'")
        id = await database.fetch_one(query2)
        query = text(f"DELETE From todo where id_todo = '{id.id}'")
        result = await database.execute(query)
        if result :
            query = (f"DELETE FROM users WHERE email = '{email}'")
            await database.execute(query)
            return {f"Successfully deleted user {email}"}
        else:
            raise HTTPException (status_code=417)
    except:
        email =  decoded_token.get("sub")
        query = (f"DELETE FROM users WHERE email = '{email}'")
        await database.execute(query)
        return {f"Successfully deleted user {email}"}
@app.put("/update/{message}")
async def update_user(user: User,message:str, Authorize: AuthJWT = Depends(), database: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])
    email =  decoded_token.get("sub")
    if message  == 'name':
        query = text(f"UPDATE users SET name = '{user.name}' where email = '{email}'")
        if user.name == "":# update name
            return "previous value saved"
        else:
            database.execute(query,{"name" : user.name}) 
            database.commit()           
            return ("updated,")
    elif message == 'office':# update office
        query = text(f"""UPDATE users SET office = '{user.office}' where email = '{email}'""")
        if user.office == "":
            return "previous value saved"    
        else:
            database.execute(query, {"office" : user.office} )
            database.commit()
            return "updated"
    elif message == 'password':#update password
        query = text(f"""UPDATE users SET password = '{user.password}' where email = '{email}'""")
        if user.password == "":
            return "previous value saved"
        else:
            database.execute(query, {"password" : ph.hash(user.password)})
            database.commit()
            return "updated"
    elif message == 'address':# update address
        query = text(f"""UPDATE users SET address = '{user.address}' where email = '{email}'""")
        if user.address == "":
            return "previous value saved"
        else:
            database.execute(query, {"address" : user.address})
            database.commit()
            return "updated"
    elif message == 'hire_date':# update hire_date
        query = text(f"""UPDATE users SET hire_date = '{user.hire_date}' where email = '{email}'""")
        if user.hire_date == "":
            return "previous value saved"
        else:
            database.execute(query, {"hiredate" : user.hire_date})
            database.commit()
            return "updated"
    elif message == 'email':#update email
        query = text(f"""UPDATE users SET email = '{user.email}' where email = '{email}'""")
        if user.email == "":
            return "previous value saved"
        else:
            database.execute(query, {"email" : user.email})
            database.commit()
            return "updated"

@app.get("/todo/read")# for delete method 
async def get_todo_list(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:    
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        query1 = (f"Select id from users where email = '{email}'")
        id = await database.fetch_one(query1)
        if id :
            query = (f"SELECT t.tasks, u.name FROM users u JOIN todo t ON u.id = t.id_todo WHERE u.email = '{email}'") 
            result = await database.fetch_one(query)
            if result:
                return result
            else :
                raise HTTPException (status_code=404,detail="user not found:")
    except:
        raise HTTPException (status_code=400,detail="error not found id")
@app.post("/todo/create")# create method
async def toodo_create(todo: todo,Authorize: AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):

    try:
        Authorize.jwt_required()
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        query1 = (f"Select id from users where email = '{email}'")
        id = await database.fetch_one(query1)
        if id:
            insert_query = text(f"""INSERT INTO todo (id_todo, tasks) VALUES ('{id.id}','{todo.tasks}')""")
            db.execute(insert_query,{
            "id": id,
            "tasks":todo.tasks
            })
            db.commit()
            raise HTTPException(status_code=200, detail="Todo created successfully")
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=400, detail="user already registered with todolist or another error")

@app.delete("/todo/delete")
async def del_todo(Authorize : AuthJWT = Depends()):

    try:    
        Authorize.jwt_required()
    
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        query1 = (f"Select id from users where email = '{email}'")
        id = await database.fetch_one(query1)
        if id :
            query = (f"DELETE From todo where id_todo = '{id.id}'")
            result = await database.execute(query)
            if result:
                return (f"Successfully delete user todo list of {email}:")
            else :
                raise HTTPException (status_code=404,detail="user not found:")
    except:
            raise HTTPException (status_code=404, detail="user not found")
   # yha pr task mangwany hain class todo se todolist k liye or join lagana he users or todo table ka email k zariye 
@app.put("/todo/update")# get method 
async def todo_update(todo: todo,Authorize : AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    try:
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        query1 = (f"Select id from users where email = '{email}'")
        id = await database.fetch_one(query1)
        query = text(f"UPDATE todo SET tasks = '{todo.tasks}' where id_todo = '{id.id}'")
        if todo.tasks == "":
                return "nothing to update"
        else:
                db.execute(query,{"tasks" : todo.tasks}) 
                db.commit()           
                return ("updated")
    except:
        raise HTTPException (status_code=404, detail= "user not found:")
    
    
#roles crud
@app.post("/roles/create")
async def create_role(role: Role, Authorize: AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    try:
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        query1 = (f"Select id from users where email = '{email}'")
        id = await database.fetch_one(query1)
        query = text("INSERT INTO roles (r_id,role_name) VALUES ('{id.id}','{role_name}')")
        db.execute(query, {"role_name": role.role_name})
        db.commit()
        return {"detail": "Role created"}
    except:
        raise HTTPException(status_code=400, detail="Role creation failed")

@app.get("/roles/read")
async def get_roles(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        query = "SELECT * FROM roles"
        roles = await database.fetch_all(query)
        return roles
    except:
        raise HTTPException(status_code=400, detail="Failed to fetch roles")

#Departments Crud 
@app.post("/departments/create")
async def create_department(dept: Department, Authorize: AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    try:
        query = text("INSERT INTO departments (department_name) VALUES (:name)")
        db.execute(query, {"name": dept.department_name})
        db.commit()
        return {"detail": "Department created"}
    except:
        raise HTTPException(status_code=400, detail="Department creation failed")

@app.get("/departments/read")
async def get_departments(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        query = "SELECT * FROM departments"
        result = await database.fetch_all(query)
        return result
    except:
        raise HTTPException(status_code=400, detail="Failed to fetch departments")

#Projects
@app.post("/projects/create")
async def create_project(project: Project, Authorize: AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    try:
        query = text("INSERT INTO projects (project_name, description) VALUES (:name, :desc)")
        db.execute(query, {"name": project.project_name, "desc": project.description})
        db.commit()
        return {"detail": "Project created"}
    except:
        raise HTTPException(status_code=400, detail="Project creation failed")

@app.get("/projects/read")
async def get_projects(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        query = "SELECT * FROM projects"
        return await database.fetch_all(query)
    except:
        raise HTTPException(status_code=400, detail="Failed to fetch projects")


#messages crud
@app.post("/messages/send")
async def send_message(msg: Message, Authorize: AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    try:
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        user_id = await database.fetch_one(f"SELECT id FROM users WHERE email='{email}'")
        if user_id:
            query = text("INSERT INTO messages (sender_id, receiver_id, message) VALUES (:sid, :rid, :msg)")
            db.execute(query, {"sid": user_id.id, "rid": msg.receiver_id, "msg": msg.message})
            db.commit()
            return {"detail": "Message sent"}
        else:
            raise HTTPException(status_code=404, detail="Sender not found")
    except:
        raise HTTPException(status_code=400, detail="Failed to send message")

@app.get("/messages/inbox")
async def get_inbox(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        user_id = await database.fetch_one(f"SELECT id FROM users WHERE email='{email}'")
        if user_id:
            query = f"SELECT * FROM messages WHERE receiver_id = '{user_id.id}'"
            return await database.fetch_all(query)
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=400, detail="Failed to fetch inbox")


#feedback crud
@app.post("/feedback/submit")
async def submit_feedback(feedback: Feedback, Authorize: AuthJWT = Depends(), db: SessionLocal = Depends(get_db)):
    Authorize.jwt_required()
    try:
        decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"])
        email = decoded_token.get("sub")
        user_id = await database.fetch_one(f"SELECT id FROM users WHERE email='{email}'")
        if user_id:
            query = text("INSERT INTO feedback (user_id, comment, rating) VALUES (:uid, :comment, :rating)")
            db.execute(query, {"uid": user_id.id, "comment": feedback.comment, "rating": feedback.rating})
            db.commit()
            return {"detail": "Feedback submitted"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=400, detail="Feedback submission failed")

@app.get("/feedback/view")
async def view_feedback(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        query = "SELECT * FROM feedback"
        return await database.fetch_all(query)
    except:
        raise HTTPException(status_code=400, detail="Failed to fetch feedback")
