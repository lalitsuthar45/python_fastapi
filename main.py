from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
from jose import jwt, JWTError
import bcrypt
import uuid

from database import SessionLocal, engine
import modals
import schemas

from google.oauth2 import id_token
from google.auth.transport import requests

from auth import create_access_token, SECRET_KEY, ALGORITHM


# ===========================
# DATABASE TABLE CREATION
# ===========================

modals.Base.metadata.create_all(bind=engine)


# ===========================
# FASTAPI APP
# ===========================

app = FastAPI(title="Savory Haven API")


# ===========================
# CORS
# ===========================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================
# DATABASE
# ===========================

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ===========================
# JWT SECURITY
# ===========================

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        email = payload.get("sub")

        if not email:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        user = db.query(modals.User).filter(
            modals.User.email == email
        ).first()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        return user

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


# ===========================
# ADMIN SECURITY
# ===========================

def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        email = payload.get("sub")
        role = payload.get("role")

        if not email:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        if role != "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )

        user = db.query(modals.User).filter(
            modals.User.email == email
        ).first()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        return user

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


# ===========================
# USER REGISTER
# ===========================

@app.post("/register")
def register(
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):

    existing = db.query(modals.User).filter(
        modals.User.email == user.email
    ).first()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    hashed = bcrypt.hashpw(
        user.password.encode(),
        bcrypt.gensalt()
    ).decode()

    new_user = modals.User(
        name=user.name,
        email=user.email,
        password=hashed
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Registration Successful",
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email
        }
    }


# ===========================
# LOGIN
# ===========================

@app.post("/login")
def login(
    user: schemas.UserLogin,
    db: Session = Depends(get_db)
):

    db_user = db.query(modals.User).filter(
        modals.User.email == user.email
    ).first()

    if not db_user:
        raise HTTPException(
            status_code=400,
            detail="User not found"
        )

    if not bcrypt.checkpw(
        user.password.encode(),
        db_user.password.encode()
    ):
        raise HTTPException(
            status_code=400,
            detail="Wrong password"
        )

    # Get role directly from MySQL
    role_result = db.execute(
        text("SELECT role FROM users WHERE email = :email"),
        {"email": db_user.email}
    ).fetchone()

    role = role_result[0] if role_result else "user"

    # Create JWT
    access_token = create_access_token({
        "sub": db_user.email,
        "role": role
    })

    return {
        "message": "Login Successful",

        "access_token": access_token,
        "token_type": "bearer",

        "user": {
            "id": db_user.id,
            "name": db_user.name,
            "email": db_user.email,
            "role": role
        }
    }


# ===========================
# GOOGLE LOGIN
# ===========================

GOOGLE_CLIENT_ID = (
    "326624240143-vu2crpq4evd1avr7t68ha42o83c3j2re.apps.googleusercontent.com"
)


@app.post("/google-login")
def google_login(
    data: schemas.GoogleLoginRequest,
    db: Session = Depends(get_db)
):

    try:

        info = id_token.verify_oauth2_token(
            data.token,
            requests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = info.get("email")
        name = info.get("name")

        if not email:
            raise HTTPException(
                status_code=400,
                detail="Email not found"
            )

        user = db.query(modals.User).filter(
            modals.User.email == email
        ).first()

        if not user:

            random_password = uuid.uuid4().hex

            hashed = bcrypt.hashpw(
                random_password.encode(),
                bcrypt.gensalt()
            ).decode()

            user = modals.User(
                name=name or email.split("@")[0],
                email=email,
                password=hashed
            )

            db.add(user)
            db.commit()
            db.refresh(user)

        # Get role
        role_result = db.execute(
            text("SELECT role FROM users WHERE email = :email"),
            {"email": user.email}
        ).fetchone()

        role = role_result[0] if role_result else "user"

        # Create JWT
        access_token = create_access_token({
            "sub": user.email,
            "role": role
        })

        return {
            "message": "Google Login Successful",

            "access_token": access_token,
            "token_type": "bearer",

            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": role
            }
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid Google token"
        )


# ===========================
# PROFILE
# ===========================

@app.get("/profile/{email}")
def get_profile(
    email: str,
    db: Session = Depends(get_db)
):

    user = db.query(modals.User).filter(
        modals.User.email == email
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "id": user.id,
        "name": user.name,
        "email": user.email
    }


@app.put("/profile")
def update_profile(
    user_data: schemas.UserUpdate,
    db: Session = Depends(get_db)
):

    user = db.query(modals.User).filter(
        modals.User.email == user_data.old_email
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    user.name = user_data.name
    user.email = user_data.email

    db.commit()
    db.refresh(user)

    return {
        "message": "Profile Updated",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email
        }
    }


# ===========================
# CHANGE PASSWORD
# ===========================

@app.put("/change-password")
def change_password(
    data: schemas.ChangePassword,
    db: Session = Depends(get_db)
):

    user = db.query(modals.User).filter(
        modals.User.email == data.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if not bcrypt.checkpw(
        data.current_password.encode(),
        user.password.encode()
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password incorrect"
        )

    hashed = bcrypt.hashpw(
        data.new_password.encode(),
        bcrypt.gensalt()
    ).decode()

    user.password = hashed

    db.commit()

    return {
        "message": "Password Changed Successfully"
    }


# ===========================
# CREATE ORDER
# ===========================

@app.post("/orders")
def create_order(
    order: schemas.OrderCreate,
    db: Session = Depends(get_db)
):

    transaction = None

    if order.payment_method != "Cash on Delivery":
        transaction = "TXN-" + uuid.uuid4().hex[:10].upper()

    new_order = modals.Order(

        user_email=order.user_email,

        customer_name=order.customer_name,
        phone=order.phone,

        address=order.address,
        city=order.city,
        pincode=order.pincode,

        payment_method=order.payment_method,

        upi_id=order.upi_id,
        card_last4=order.card_last4,

        payment_status=(
            "Pending"
            if order.payment_method == "Cash on Delivery"
            else "Paid"
        ),

        transaction_id=transaction,

        items_total=order.items_total,
        gst=order.gst,
        delivery_charge=order.delivery_charge,
        discount=order.discount,
        grand_total=order.grand_total,

        status="Pending"
    )

    db.add(new_order)

    db.commit()
    db.refresh(new_order)

    for item in order.items:

        db.add(
            modals.OrderItem(
                order_id=new_order.id,
                food_name=item.food_name,
                price=item.price,
                quantity=item.quantity,
                subtotal=item.subtotal,
            )
        )

    db.commit()

    return {
        "message": "Order Placed Successfully",
        "order_id": new_order.id,
        "transaction_id": transaction,
        "payment_status": new_order.payment_status,
        "grand_total": new_order.grand_total,
    }


# ===========================
# MY ORDERS
# ===========================

@app.get("/orders/{user_email}")
def get_orders(
    user_email: str,
    db: Session = Depends(get_db)
):

    orders = (
        db.query(modals.Order)
        .filter(modals.Order.user_email == user_email)
        .order_by(modals.Order.id.desc())
        .all()
    )

    return [

        {
            "id": order.id,
            "user_email": order.user_email,

            "customer_name": order.customer_name,
            "phone": order.phone,

            "address": order.address,
            "city": order.city,
            "pincode": order.pincode,

            "payment_method": order.payment_method,
            "payment_status": order.payment_status,

            "transaction_id": order.transaction_id,

            "items_total": order.items_total,
            "gst": order.gst,
            "delivery_charge": order.delivery_charge,
            "discount": order.discount,
            "grand_total": order.grand_total,

            "status": order.status,

            "items": [

                {
                    "food_name": item.food_name,
                    "price": item.price,
                    "quantity": item.quantity,
                    "subtotal": item.subtotal,
                }

                for item in order.items
            ],
        }

        for order in orders
    ]


# ===========================
# CANCEL ORDER
# USER CAN CANCEL ONLY
# WHEN STATUS IS PENDING
# ===========================

@app.put("/orders/{order_id}/cancel")
def cancel_order(
    order_id: int,
    db: Session = Depends(get_db)
):

    order = (
        db.query(modals.Order)
        .filter(modals.Order.id == order_id)
        .first()
    )

    if not order:
        raise HTTPException(
            status_code=404,
            detail="Order not found"
        )

    if order.status != "Pending":

        raise HTTPException(
            status_code=400,
            detail="Order can only be cancelled while it is Pending"
        )

    order.status = "Cancelled"

    db.commit()
    db.refresh(order)

    return {
        "message": "Order Cancelled Successfully",
        "status": order.status
    }


# ===========================
# CREATE RESERVATION
# ===========================

@app.post("/reservations")
def create_reservation(
    reservation: schemas.ReservationCreate,
    db: Session = Depends(get_db)
):

    new_reservation = modals.Reservation(

        user_email=reservation.user_email,

        name=reservation.name,
        phone=reservation.phone,

        guests=reservation.guests,

        reservation_date=reservation.reservation_date,
        reservation_time=reservation.reservation_time,

        occasion=reservation.occasion,
        table_type=reservation.table_type,

        special_request=reservation.special_request,

        status="Pending"
    )

    db.add(new_reservation)

    db.commit()
    db.refresh(new_reservation)

    return {
        "message": "Table Reserved Successfully",
        "reservation_id": new_reservation.id,
        "status": new_reservation.status,
    }


# ===========================
# MY RESERVATIONS
# ===========================

@app.get("/reservations/{user_email}")
def get_user_reservations(
    user_email: str,
    db: Session = Depends(get_db)
):

    reservations = (
        db.query(modals.Reservation)
        .filter(
            modals.Reservation.user_email == user_email
        )
        .order_by(modals.Reservation.id.desc())
        .all()
    )

    return [

        {
            "id": r.id,
            "user_email": r.user_email,

            "name": r.name,
            "phone": r.phone,

            "guests": r.guests,

            "reservation_date": r.reservation_date,
            "reservation_time": r.reservation_time,

            "occasion": r.occasion,
            "table_type": r.table_type,

            "special_request": r.special_request,

            "status": r.status,
        }

        for r in reservations
    ]


# ===========================
# CANCEL RESERVATION
# ===========================

@app.put("/reservations/{reservation_id}/cancel")
def cancel_reservation(
    reservation_id: int,
    db: Session = Depends(get_db)
):

    reservation = (
        db.query(modals.Reservation)
        .filter(
            modals.Reservation.id == reservation_id
        )
        .first()
    )

    if not reservation:

        raise HTTPException(
            status_code=404,
            detail="Reservation not found"
        )

    if reservation.status in [
        "Completed",
        "Cancelled"
    ]:

        raise HTTPException(
            status_code=400,
            detail="Reservation cannot be cancelled now"
        )

    reservation.status = "Cancelled"

    db.commit()

    return {
        "message": "Reservation Cancelled Successfully"
    }


# ==================================================
# ADMIN - ALL ORDERS
# ==================================================

@app.get("/admin/orders")
def admin_orders(
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db)
):

    orders = (
        db.query(modals.Order)
        .order_by(modals.Order.id.desc())
        .all()
    )

    return [

        {
            "id": order.id,
            "user_email": order.user_email,

            "customer_name": order.customer_name,
            "phone": order.phone,

            "address": order.address,
            "city": order.city,
            "pincode": order.pincode,

            "payment_method": order.payment_method,
            "payment_status": order.payment_status,

            "transaction_id": order.transaction_id,

            "items_total": order.items_total,
            "gst": order.gst,
            "delivery_charge": order.delivery_charge,
            "discount": order.discount,
            "grand_total": order.grand_total,

            "status": order.status,

            "items": [

                {
                    "food_name": item.food_name,
                    "price": item.price,
                    "quantity": item.quantity,
                    "subtotal": item.subtotal,
                }

                for item in order.items
            ],
        }

        for order in orders
    ]


# ==================================================
# ADMIN UPDATE ORDER STATUS
# ==================================================

@app.put("/admin/orders/{order_id}/status")
def update_order_status(

    order_id: int,
    status: str,

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db)
):

    allowed_statuses = [

        "Pending",
        "Confirmed",
        "Preparing",
        "Out For Delivery",
        "Delivered",
        "Cancelled",

    ]

    if status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid order status"
        )

    order = (
        db.query(modals.Order)
        .filter(
            modals.Order.id == order_id
        )
        .first()
    )

    if not order:

        raise HTTPException(
            status_code=404,
            detail="Order not found"
        )

    order.status = status

    db.commit()
    db.refresh(order)

    return {

        "message": "Order Status Updated",
        "status": order.status

    }


# ==================================================
# ADMIN - ALL RESERVATIONS
# ==================================================

@app.get("/admin/reservations")
def admin_reservations(

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db)
):

    reservations = (

        db.query(modals.Reservation)

        .order_by(
            modals.Reservation.id.desc()
        )

        .all()
    )

    return [

        {
            "id": r.id,

            "user_email": r.user_email,

            "name": r.name,
            "phone": r.phone,

            "guests": r.guests,

            "reservation_date": r.reservation_date,
            "reservation_time": r.reservation_time,

            "occasion": r.occasion,
            "table_type": r.table_type,

            "special_request": r.special_request,

            "status": r.status,
        }

        for r in reservations
    ]


# ==================================================
# ADMIN UPDATE RESERVATION STATUS
# ==================================================

@app.put(
    "/admin/reservations/{reservation_id}/status"
)
def update_reservation_status(

    reservation_id: int,

    status: str,

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db)
):

    reservation = (

        db.query(modals.Reservation)

        .filter(
            modals.Reservation.id == reservation_id
        )

        .first()
    )

    if not reservation:

        raise HTTPException(
            status_code=404,
            detail="Reservation not found"
        )

    reservation.status = status

    db.commit()

    return {
        "message": "Reservation Status Updated"
    }


# ==================================================
# USERS
# ONLY ADMIN CAN SEE ALL USERS
# ==================================================

@app.get("/users")
def users(

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db)
):

    users = db.query(modals.User).all()

    return [

        {
            "id": u.id,
            "name": u.name,
            "email": u.email,
        }

        for u in users
    ]


# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.get("/admin/dashboard")
def dashboard(

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db)
):

    total_users = (
        db.query(modals.User)
        .count()
    )

    total_orders = (
        db.query(modals.Order)
        .count()
    )

    total_reservations = (
        db.query(modals.Reservation)
        .count()
    )

    paid_orders = (

        db.query(modals.Order)

        .filter(
            modals.Order.payment_status == "Paid"
        )

        .all()
    )

    total_revenue = sum(

        order.grand_total or 0

        for order in paid_orders
    )

    return {

        "total_users": total_users,

        "total_orders": total_orders,

        "total_reservations": total_reservations,

        "revenue": total_revenue

    }