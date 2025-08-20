from fastapi import FastAPI, HTTPException, Form, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, Any, List
from datetime import datetime, timedelta
import mysql.connector
import hashlib
import jwt
import io
import csv
import json
import razorpay

# ==============================
# Config
# ==============================
APP_TITLE = "Indus Cup API"
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Password",          # <-- change to your MySQL password
    "database": "indus_cup",
}
SECRET_KEY = "ChangeThisSecretKey!"  # <-- change in production
ALGORITHM = "algo"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

TEAM_SPORTS = {
    "cricket": "team_cricket",
    "football": "team_football",
    "basketball": "team_basketball",
}
INDIVIDUAL_SPORTS = {
    "badminton": "individual_badminton",
    "chess": "individual_chess",
}

# Razorpay credentials (set your real keys)
RAZORPAY_KEY_ID = "rzp_test_xxxxxx"
RAZORPAY_KEY_SECRET = "xxxxxxxxxxxxxxxx"
RAZORPAY_WEBHOOK_SECRET = "webhook_secret_value"
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# ==============================
# App & CORS
# ==============================
app = FastAPI(title=APP_TITLE, version="3.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()

# ==============================
# Helpers
# ==============================
def db_conn():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"DB connection error: {e}")

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def create_token(sub: str, role: str):
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": sub, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, str]:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return {"Uid": payload["sub"], "role": payload["role"]}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_admin(u=Depends(current_user)):
    if u["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
    return u

def gen_uid(cur) -> str:
    cur.execute("SELECT COUNT(*) FROM user_master")
    n = cur.fetchone()[0] + 1
    return f"INDUS{n:03d}"

def gen_team_id(prefix: str, cur, table: str) -> str:
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    n = cur.fetchone()[0] + 1
    return f"T-{prefix.upper()}-{n:04d}"

def gen_player_id(prefix: str, cur, table: str) -> str:
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    n = cur.fetchone()[0] + 1
    return f"P-{prefix.upper()}-{n:04d}"

def ensure_allowed_sport_team(sport: str):
    if sport not in TEAM_SPORTS:
        raise HTTPException(status_code=400, detail=f"Unknown team sport: {sport}")

def ensure_allowed_sport_individual(sport: str):
    if sport not in INDIVIDUAL_SPORTS:
        raise HTTPException(status_code=400, detail=f"Unknown individual sport: {sport}")

# Attempt to update order in team tables; returns True if matched
def _update_team_order_status(conn, order_id: str, payment_id: str, new_status: str) -> bool:
    cur = conn.cursor()
    try:
        for table in TEAM_SPORTS.values():
            cur.execute(f"SELECT Team_id, status FROM {table} WHERE order_id=%s", (order_id,))
            row = cur.fetchone()
            if row:
                _, status = row
                if status == "PENDING_PAYMENT":
                    cur.execute(
                        f"UPDATE {table} SET payment_id=%s, status=%s WHERE order_id=%s",
                        (payment_id, new_status, order_id)
                    )
                    conn.commit()
                return True
        return False
    finally:
        cur.close()

# Attempt to update order in individual tables; returns True if matched
def _update_individual_order_status(conn, order_id: str, payment_id: str, new_status: str) -> bool:
    cur = conn.cursor()
    try:
        for table in INDIVIDUAL_SPORTS.values():
            cur.execute(f"SELECT player_id, status FROM {table} WHERE order_id=%s", (order_id,))
            row = cur.fetchone()
            if row:
                _, status = row
                if status == "PENDING_PAYMENT":
                    cur.execute(
                        f"UPDATE {table} SET payment_id=%s, status=%s WHERE order_id=%s",
                        (payment_id, new_status, order_id)
                    )
                    conn.commit()
                return True
        return False
    finally:
        cur.close()

# ==============================
# Models
# ==============================
class PublicRegister(BaseModel):
    First_Name: str
    Last_Name: str
    collage_name: str
    Collage_id: str
    Cont_no: str
    Email: str
    password: str

class LoginModel(BaseModel):
    Uid: str
    password: str

class CaptainPayload(BaseModel):
    name: str
    number: str
    email: str
    Collage_id: str
    Collage_id_img: str

class ViceCaptainPayload(BaseModel):
    name: str
    number: str
    email: str
    Collage_id: str
    Collage_id_img: str

class TeamPlayersPayload(BaseModel):
    Player_details: List[Dict[str, Any]]

# ==============================
# Public Auth
# ==============================
@app.post("/api/public/register")
def public_register(payload: PublicRegister):
    conn = db_conn()
    cur = conn.cursor()
    try:
        Uid = gen_uid(cur)
        pw_hash = hash_password(payload.password)
        cur.execute("""
            INSERT INTO user_master
              (Uid, password, First_Name, Last_Name, collage_name, Collage_id, Cont_no, Email, user_role)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'USER')
        """, (Uid, pw_hash, payload.First_Name, payload.Last_Name, payload.collage_name,
              payload.Collage_id, payload.Cont_no, payload.Email))
        conn.commit()
        return {"success": True, "Uid": Uid, "message": "Account created. Use your Uid to login."}
    finally:
        cur.close()
        conn.close()

@app.post("/api/auth/login")
def login(payload: LoginModel):
    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT Uid, password, user_role FROM user_master WHERE Uid=%s", (payload.Uid,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        Uid, pw_hash, role = row
        if hash_password(payload.password) != pw_hash:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_token(Uid, role)
        return {"access_token": token, "token_type": "bearer", "Uid": Uid, "role": role}
    finally:
        cur.close()
        conn.close()

# ==============================
# Team Sports: Register → Pay → Finalize
# ==============================
@app.post("/api/team/{sport}/register")
def team_register(
    sport: str,
    Team_no: str = Form(...),
    collage_name: str = Form(...),
    captain: str = Form(...),  # JSON string
    vice: str = Form(...),     # JSON string
    u=Depends(current_user),
):
    ensure_allowed_sport_team(sport)
    table = TEAM_SPORTS[sport]
    conn = db_conn()
    cur = conn.cursor()
    try:
        # Validate captain/vice JSON
        try:
            captain_data = CaptainPayload(**json.loads(captain))
            vice_data = ViceCaptainPayload(**json.loads(vice))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid captain/vice JSON: {e}")

        # Generate Team_id
        team_id = gen_team_id(sport, cur, table)

        # Create Razorpay order
        order = razorpay_client.order.create({
            "amount": 10000,            # amount in paise (₹100) -> replace as needed
            "currency": "INR",
            "payment_capture": 1
        })
        order_id = order["id"]

        # Insert DB with PENDING_PAYMENT
        cur.execute(f"""
            INSERT INTO {table}
              (Team_id, Team_no, collage_name, Captain_details, Vice_Captain_details,
               Player_details, registrar_uid, status, order_id, payment_id)
            VALUES (%s,%s,%s,%s,%s,NULL,%s,'PENDING_PAYMENT',%s,NULL)
        """, (team_id, Team_no, collage_name, captain_data.json(), vice_data.json(), u["Uid"], order_id))
        conn.commit()

        return {"success": True, "Team_id": team_id, "order_id": order_id, "razorpay_key_id": RAZORPAY_KEY_ID, "status": "PENDING_PAYMENT"}
    finally:
        cur.close()
        conn.close()

@app.post("/api/team/{sport}/{team_id}/players")
def team_add_players(sport: str, team_id: str, payload: TeamPlayersPayload, u=Depends(current_user)):
    ensure_allowed_sport_team(sport)
    table = TEAM_SPORTS[sport]
    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT registrar_uid, status FROM {table} WHERE Team_id=%s", (team_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Team not found")
        registrar_uid, status = row
        if registrar_uid != u["Uid"] and u["role"] != "ADMIN":
            raise HTTPException(status_code=403, detail="Not allowed")
        if status != "PAYMENT_DONE":
            raise HTTPException(status_code=400, detail="Players can be added only after successful payment")

        # Validate players JSON (required fields + uniqueness within team)
        seen_player_no, seen_number, seen_email, seen_collage_id = set(), set(), set(), set()
        for p in payload.Player_details:
            for field in ["player_no", "name", "number", "email", "Collage_id", "Collage_id_img"]:
                if field not in p:
                    raise HTTPException(status_code=400, detail=f"Missing {field} in player")
            if p["player_no"] in seen_player_no: raise HTTPException(status_code=400, detail=f"Duplicate player_no {p['player_no']}")
            if p["number"] in seen_number: raise HTTPException(status_code=400, detail=f"Duplicate number {p['number']}")
            if p["email"] in seen_email: raise HTTPException(status_code=400, detail=f"Duplicate email {p['email']}")
            if p["Collage_id"] in seen_collage_id: raise HTTPException(status_code=400, detail=f"Duplicate Collage_id {p['Collage_id']}")
            seen_player_no.add(p["player_no"]); seen_number.add(p["number"]); seen_email.add(p["email"]); seen_collage_id.add(p["Collage_id"])

        cur.execute(
            f"UPDATE {table} SET Player_details=%s, status='FINALIZED' WHERE Team_id=%s",
            (json.dumps(payload.Player_details), team_id)
        )
        conn.commit()
        return {"success": True, "Team_id": team_id, "status": "FINALIZED"}
    finally:
        cur.close()
        conn.close()

# ==============================
# Individual Sports: Register(all details) → Pay(finalize)
# ==============================
@app.post("/api/individual/{sport}/register")
def individual_register(
    sport: str,
    player_no: str = Form(...),
    collage_name: str = Form(...),
    name: str = Form(...),
    number: str = Form(...),
    email: str = Form(...),
    Collage_id: str = Form(...),
    Collage_id_img: str = Form(...),
    u=Depends(current_user)
):
    ensure_allowed_sport_individual(sport)
    table = INDIVIDUAL_SPORTS[sport]
    conn = db_conn()
    cur = conn.cursor()
    try:
        # Generate player_id
        player_id = gen_player_id(sport, cur, table)

        # Create Razorpay order
        order = razorpay_client.order.create({
            "amount": 5000,             # amount in paise (₹50) -> replace as needed
            "currency": "INR",
            "payment_capture": 1
        })
        order_id = order["id"]

        # Insert DB with all details + PENDING_PAYMENT
        cur.execute(f"""
            INSERT INTO {table}
              (player_id, player_no, collage_name, name, number, email,
               Collage_id, Collage_id_img, registrar_uid, status, order_id, payment_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING_PAYMENT',%s,NULL)
        """, (player_id, player_no, collage_name, name, number, email,
              Collage_id, Collage_id_img, u["Uid"], order_id))
        conn.commit()

        return {"success": True, "player_id": player_id, "order_id": order_id, "razorpay_key_id": RAZORPAY_KEY_ID, "status": "PENDING_PAYMENT"}
    finally:
        cur.close()
        conn.close()

# ==============================
# Razorpay Webhook (verifies & advances state)
# ==============================
@app.post("/api/payment/webhook")
async def payment_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature")
    try:
        razorpay_client.utility.verify_webhook_signature(body, signature, RAZORPAY_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signature verification failed: {e}")

    payload = json.loads(body.decode())
    # Safely extract order/payment/status (protect if webhook shape varies)
    try:
        entity = payload["payload"]["payment"]["entity"]
        order_id = entity["order_id"]
        payment_id = entity["id"]
        status = entity["status"]  # 'captured' for success
    except Exception:
        # ignore unrelated webhook events
        return {"ok": True, "ignored": True}

    conn = db_conn()
    try:
        if status == "captured":
            # TEAM: set PAYMENT_DONE
            matched_team = _update_team_order_status(conn, order_id, payment_id, "PAYMENT_DONE")
            # INDIVIDUAL: finalize directly
            matched_ind = _update_individual_order_status(conn, order_id, payment_id, "FINALIZED")
            if not matched_team and not matched_ind:
                # No matching order; log but don't fail webhook
                return {"ok": True, "warning": "order_id not found"}
            return {"ok": True}
        else:
            # Payment failed/authorized/refunded etc. No state advance.
            return {"ok": True, "note": f"Payment status={status}, no update"}
    finally:
        conn.close()

# ==============================
# My Registrations
# ==============================
@app.get("/api/my_registrations")
def my_registrations(u=Depends(current_user)):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    try:
        results = []
        for sport, table in TEAM_SPORTS.items():
            cur.execute(f"SELECT Team_id, Team_no, collage_name, status FROM {table} WHERE registrar_uid=%s", (u["Uid"],))
            results.extend([{"type":"team","sport":sport,**r} for r in cur.fetchall()])
        for sport, table in INDIVIDUAL_SPORTS.items():
            cur.execute(f"SELECT player_id, player_no, collage_name, status FROM {table} WHERE registrar_uid=%s", (u["Uid"],))
            results.extend([{"type":"individual","sport":sport,**r} for r in cur.fetchall()])
        return {"success": True, "data": results}
    finally:
        cur.close()
        conn.close()

# ==============================
# Admin APIs
# ==============================
@app.get("/api/admin/registrations")
def admin_registrations(_=Depends(require_admin)):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    try:
        all_data = {}
        for sport, table in {**TEAM_SPORTS, **INDIVIDUAL_SPORTS}.items():
            cur.execute(f"SELECT * FROM {table}")
            all_data[sport] = cur.fetchall()
        return {"success": True, "data": all_data}
    finally:
        cur.close()
        conn.close()

@app.get("/api/admin/export")
def admin_export_csv(type: str, sport: str, _=Depends(require_admin)):
    if type not in ("team","individual"):
        raise HTTPException(status_code=400, detail="type must be team or individual")
    conn = db_conn()
    cur = conn.cursor()
    output = io.StringIO()
    writer = csv.writer(output)
    try:
        if type == "team":
            ensure_allowed_sport_team(sport)
            table = TEAM_SPORTS[sport]
            writer.writerow(["Team_id","Team_no","Collage","Status"])
            cur.execute(f"SELECT Team_id,Team_no,collage_name,status FROM {table}")
            for r in cur.fetchall(): writer.writerow(r)
        else:
            ensure_allowed_sport_individual(sport)
            table = INDIVIDUAL_SPORTS[sport]
            writer.writerow(["Player_id","Player_no","Collage","Status"])
            cur.execute(f"SELECT player_id,player_no,collage_name,status FROM {table}")
            for r in cur.fetchall(): writer.writerow(r)
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv")
    finally:
        cur.close()
        conn.close()

# ==============================
# Health
# ==============================
@app.get("/api/health")
def health():
    return {"ok": True, "time": datetime.utcnow().isoformat()}
