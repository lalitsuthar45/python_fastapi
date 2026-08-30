
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

from auth import (
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
)


# =========================================================
# DATABASE TABLE CREATION
# =========================================================

modals.Base.metadata.create_all(bind=engine)


# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI(
    title="Savory Haven API"
)


# =========================================================
# CORS
# =========================================================
#
# Development ke liye "*" rakha gaya hai.
#
# Production me apni Netlify URL ko yahan add karna
# aur "*" remove karna better hai.
#
# Example:
#
# allow_origins=[
#     "https://your-site.netlify.app"
# ]
#
# =========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# =========================================================
# DATABASE
# =========================================================

def get_db():

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()


# =========================================================
# JWT SECURITY
# =========================================================

security = HTTPBearer()


# =========================================================
# GET CURRENT USER
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
    db: Session = Depends(get_db),
):

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        email = payload.get("sub")

        if not email:

            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token",
            )

        user = (
            db.query(modals.User)
            .filter(
                modals.User.email == email
            )
            .first()
        )

        if not user:

            raise HTTPException(
                status_code=401,
                detail="User account no longer exists",
            )

        return user

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token",
        )


# =========================================================
# GET CURRENT ADMIN
# =========================================================

def get_current_admin(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    role_result = db.execute(
        text(
            """
            SELECT role
            FROM users
            WHERE email = :email
            """
        ),
        {
            "email": current_user.email
        },
    ).fetchone()

    role = (
        role_result[0]
        if role_result
        else "user"
    )

    if role != "admin":

        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return current_user


# =========================================================
# HELPER - GET USER ROLE
# =========================================================

def get_user_role(
    email: str,
    db: Session,
):

    role_result = db.execute(
        text(
            """
            SELECT role
            FROM users
            WHERE email = :email
            """
        ),
        {
            "email": email
        },
    ).fetchone()

    return (
        role_result[0]
        if role_result
        else "user"
    )


# =========================================================
# REGISTER
# =========================================================

@app.post("/register")
def register(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
):

    email = user.email.strip().lower()
    name = user.name.strip()

    if not name or not email or not user.password:

        raise HTTPException(
            status_code=400,
            detail="All fields are required",
        )

    existing = (
        db.query(modals.User)
        .filter(
            modals.User.email == email
        )
        .first()
    )

    if existing:

        raise HTTPException(
            status_code=400,
            detail="Email already exists",
        )

    hashed = bcrypt.hashpw(
        user.password.encode(),
        bcrypt.gensalt(),
    ).decode()

    new_user = modals.User(
        name=name,
        email=email,
        password=hashed,
    )

    db.add(new_user)

    db.commit()

    db.refresh(new_user)

    # New users are normal users
    role = "user"

    access_token = create_access_token(
        {
            "sub": new_user.email,
            "role": role,
        }
    )

    return {

        "message": "Registration Successful",

        "access_token": access_token,

        "token_type": "bearer",

        "user": {

            "id": new_user.id,

            "name": new_user.name,

            "email": new_user.email,

            "role": role,
        },
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/login")
def login(
    user: schemas.UserLogin,
    db: Session = Depends(get_db),
):

    email = user.email.strip().lower()

    db_user = (
        db.query(modals.User)
        .filter(
            modals.User.email == email
        )
        .first()
    )

    if not db_user:

        raise HTTPException(
            status_code=400,
            detail="Invalid email or password",
        )

    if not bcrypt.checkpw(
        user.password.encode(),
        db_user.password.encode(),
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid email or password",
        )

    role = get_user_role(
        db_user.email,
        db,
    )

    access_token = create_access_token(
        {
            "sub": db_user.email,
            "role": role,
        }
    )

    return {

        "message": "Login Successful",

        "access_token": access_token,

        "token_type": "bearer",

        "user": {

            "id": db_user.id,

            "name": db_user.name,

            "email": db_user.email,

            "role": role,
        },
    }


# =========================================================
# GOOGLE LOGIN
# =========================================================

GOOGLE_CLIENT_ID = (
    "326624240143-vu2crpq4evd1avr7t68ha42o83c3j2re.apps.googleusercontent.com"
)


@app.post("/google-login")
def google_login(
    data: schemas.GoogleLoginRequest,
    db: Session = Depends(get_db),
):

    try:

        info = id_token.verify_oauth2_token(
            data.token,
            requests.Request(),
            GOOGLE_CLIENT_ID,
        )

        email = info.get("email")

        name = info.get("name")

        if not email:

            raise HTTPException(
                status_code=400,
                detail="Google account email not found",
            )

        email = email.strip().lower()

        user = (
            db.query(modals.User)
            .filter(
                modals.User.email == email
            )
            .first()
        )

        if not user:

            random_password = uuid.uuid4().hex

            hashed = bcrypt.hashpw(
                random_password.encode(),
                bcrypt.gensalt(),
            ).decode()

            user = modals.User(
                name=(
                    name
                    or email.split("@")[0]
                ),
                email=email,
                password=hashed,
            )

            db.add(user)

            db.commit()

            db.refresh(user)

        role = get_user_role(
            user.email,
            db,
        )

        access_token = create_access_token(
            {
                "sub": user.email,
                "role": role,
            }
        )

        return {

            "message": "Google Login Successful",

            "access_token": access_token,

            "token_type": "bearer",

            "user": {

                "id": user.id,

                "name": user.name,

                "email": user.email,

                "role": role,
            },
        }

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Google Login Error:",
            error
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid Google token",
        )


# =========================================================
# CURRENT USER
# =========================================================

@app.get("/me")
def get_me(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    role = get_user_role(
        current_user.email,
        db,
    )

    return {

        "user": {

            "id": current_user.id,

            "name": current_user.name,

            "email": current_user.email,

            "role": role,
        }
    }


# =========================================================
# PROFILE
# =========================================================

@app.get("/profile/{email}")
def get_profile(
    email: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    email = email.strip().lower()

    if email != current_user.email.lower():

        raise HTTPException(
            status_code=403,
            detail="You can only access your own profile",
        )

    user = (
        db.query(modals.User)
        .filter(
            modals.User.email == current_user.email
        )
        .first()
    )

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return {

        "id": user.id,

        "name": user.name,

        "email": user.email,
    }


# =========================================================
# UPDATE PROFILE
# =========================================================

@app.put("/profile")
def update_profile(
    user_data: schemas.UserUpdate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    old_email = (
        user_data.old_email
        .strip()
        .lower()
    )

    new_email = (
        user_data.email
        .strip()
        .lower()
    )

    if old_email != current_user.email.lower():

        raise HTTPException(
            status_code=403,
            detail="You can only update your own profile",
        )

    existing = (
        db.query(modals.User)
        .filter(
            modals.User.email == new_email
        )
        .first()
    )

    if (
        existing
        and existing.id != current_user.id
    ):

        raise HTTPException(
            status_code=400,
            detail="Email already exists",
        )

    current_user.name = user_data.name.strip()

    current_user.email = new_email

    db.commit()

    db.refresh(current_user)

    return {

        "message": "Profile Updated",

        "user": {

            "id": current_user.id,

            "name": current_user.name,

            "email": current_user.email,
        },
    }


# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.put("/change-password")
def change_password(
    data: schemas.ChangePassword,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    email = data.email.strip().lower()

    if email != current_user.email.lower():

        raise HTTPException(
            status_code=403,
            detail="You can only change your own password",
        )

    if not bcrypt.checkpw(
        data.current_password.encode(),
        current_user.password.encode(),
    ):

        raise HTTPException(
            status_code=400,
            detail="Current password incorrect",
        )

    hashed = bcrypt.hashpw(
        data.new_password.encode(),
        bcrypt.gensalt(),
    ).decode()

    current_user.password = hashed

    db.commit()

    return {

        "message":
            "Password Changed Successfully"
    }


# =========================================================
# CREATE ORDER
# =========================================================

@app.post("/orders")
def create_order(
    order: schemas.OrderCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    order_email = (
        order.user_email
        .strip()
        .lower()
    )

    if order_email != current_user.email.lower():

        raise HTTPException(
            status_code=403,
            detail="You can only create orders for your own account",
        )

    transaction = None

    if (
        order.payment_method
        != "Cash on Delivery"
    ):

        transaction = (
            "TXN-"
            + uuid.uuid4()
            .hex[:10]
            .upper()
        )

    new_order = modals.Order(

        user_email=current_user.email,

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
            if order.payment_method
            == "Cash on Delivery"
            else "Paid"
        ),

        transaction_id=transaction,

        items_total=order.items_total,

        gst=order.gst,

        delivery_charge=order.delivery_charge,

        discount=order.discount,

        grand_total=order.grand_total,

        status="Pending",
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

        "message":
            "Order Placed Successfully",

        "order_id":
            new_order.id,

        "transaction_id":
            transaction,

        "payment_status":
            new_order.payment_status,

        "grand_total":
            new_order.grand_total,
    }


# =========================================================
# MY ORDERS
# =========================================================

@app.get("/orders/{user_email}")
def get_orders(
    user_email: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    user_email = (
        user_email
        .strip()
        .lower()
    )

    if user_email != current_user.email.lower():

        raise HTTPException(
            status_code=403,
            detail="You can only access your own orders",
        )

    orders = (
        db.query(modals.Order)
        .filter(
            modals.Order.user_email
            == current_user.email
        )
        .order_by(
            modals.Order.id.desc()
        )
        .all()
    )

    return [

        {

            "id": order.id,

            "user_email": order.user_email,

            "customer_name":
                order.customer_name,

            "phone":
                order.phone,

            "address":
                order.address,

            "city":
                order.city,

            "pincode":
                order.pincode,

            "payment_method":
                order.payment_method,

            "payment_status":
                order.payment_status,

            "transaction_id":
                order.transaction_id,

            "items_total":
                order.items_total,

            "gst":
                order.gst,

            "delivery_charge":
                order.delivery_charge,

            "discount":
                order.discount,

            "grand_total":
                order.grand_total,

            "status":
                order.status,

            "items": [

                {

                    "food_name":
                        item.food_name,

                    "price":
                        item.price,

                    "quantity":
                        item.quantity,

                    "subtotal":
                        item.subtotal,

                }

                for item in order.items
            ],
        }

        for order in orders
    ]


# =========================================================
# CANCEL ORDER
# =========================================================

@app.put("/orders/{order_id}/cancel")
def cancel_order(
    order_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

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
            detail="Order not found",
        )

    if (
        order.user_email.lower()
        != current_user.email.lower()
    ):

        raise HTTPException(
            status_code=403,
            detail="You can only cancel your own order",
        )

    if order.status != "Pending":

        raise HTTPException(
            status_code=400,
            detail=(
                "Order can only be cancelled "
                "while it is Pending"
            ),
        )

    order.status = "Cancelled"

    db.commit()

    db.refresh(order)

    return {

        "message":
            "Order Cancelled Successfully",

        "status":
            order.status,
    }


# =========================================================
# CREATE RESERVATION
# =========================================================

@app.post("/reservations")
def create_reservation(
    reservation: schemas.ReservationCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    reservation_email = (
        reservation.user_email
        .strip()
        .lower()
    )

    if (
        reservation_email
        != current_user.email.lower()
    ):

        raise HTTPException(
            status_code=403,
            detail=(
                "You can only create reservations "
                "for your own account"
            ),
        )

    new_reservation = modals.Reservation(

        user_email=current_user.email,

        name=reservation.name,

        phone=reservation.phone,

        guests=reservation.guests,

        reservation_date=
            reservation.reservation_date,

        reservation_time=
            reservation.reservation_time,

        occasion=reservation.occasion,

        table_type=reservation.table_type,

        special_request=
            reservation.special_request,

        status="Pending",
    )

    db.add(new_reservation)

    db.commit()

    db.refresh(new_reservation)

    return {

        "message":
            "Table Reserved Successfully",

        "reservation_id":
            new_reservation.id,

        "status":
            new_reservation.status,
    }


# =========================================================
# MY RESERVATIONS
# =========================================================

@app.get("/reservations/{user_email}")
def get_user_reservations(
    user_email: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    user_email = (
        user_email
        .strip()
        .lower()
    )

    if user_email != current_user.email.lower():

        raise HTTPException(
            status_code=403,
            detail=(
                "You can only access your own reservations"
            ),
        )

    reservations = (

        db.query(modals.Reservation)

        .filter(
            modals.Reservation.user_email
            == current_user.email
        )

        .order_by(
            modals.Reservation.id.desc()
        )

        .all()
    )

    return [

        {

            "id": r.id,

            "user_email":
                r.user_email,

            "name":
                r.name,

            "phone":
                r.phone,

            "guests":
                r.guests,

            "reservation_date":
                r.reservation_date,

            "reservation_time":
                r.reservation_time,

            "occasion":
                r.occasion,

            "table_type":
                r.table_type,

            "special_request":
                r.special_request,

            "status":
                r.status,
        }

        for r in reservations
    ]


# =========================================================
# CANCEL RESERVATION
# =========================================================

@app.put(
    "/reservations/{reservation_id}/cancel"
)
def cancel_reservation(
    reservation_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    reservation = (

        db.query(modals.Reservation)

        .filter(
            modals.Reservation.id
            == reservation_id
        )

        .first()
    )

    if not reservation:

        raise HTTPException(
            status_code=404,
            detail="Reservation not found",
        )

    if (
        reservation.user_email.lower()
        != current_user.email.lower()
    ):

        raise HTTPException(
            status_code=403,
            detail=(
                "You can only cancel "
                "your own reservation"
            ),
        )

    if reservation.status in [
        "Completed",
        "Cancelled",
    ]:

        raise HTTPException(
            status_code=400,
            detail=(
                "Reservation cannot be "
                "cancelled now"
            ),
        )

    reservation.status = "Cancelled"

    db.commit()

    return {

        "message":
            "Reservation Cancelled Successfully"
    }


# =========================================================
# ADMIN - ALL ORDERS
# =========================================================

@app.get("/admin/orders")
def admin_orders(
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
):

    orders = (

        db.query(modals.Order)

        .order_by(
            modals.Order.id.desc()
        )

        .all()
    )

    return [

        {

            "id": order.id,

            "user_email":
                order.user_email,

            "customer_name":
                order.customer_name,

            "phone":
                order.phone,

            "address":
                order.address,

            "city":
                order.city,

            "pincode":
                order.pincode,

            "payment_method":
                order.payment_method,

            "payment_status":
                order.payment_status,

            "transaction_id":
                order.transaction_id,

            "items_total":
                order.items_total,

            "gst":
                order.gst,

            "delivery_charge":
                order.delivery_charge,

            "discount":
                order.discount,

            "grand_total":
                order.grand_total,

            "status":
                order.status,

            "items": [

                {

                    "food_name":
                        item.food_name,

                    "price":
                        item.price,

                    "quantity":
                        item.quantity,

                    "subtotal":
                        item.subtotal,
                }

                for item in order.items
            ],
        }

        for order in orders
    ]


# =========================================================
# ADMIN UPDATE ORDER STATUS
# =========================================================

@app.put(
    "/admin/orders/{order_id}/status"
)
def update_order_status(

    order_id: int,

    status: str,

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db),
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
            detail="Invalid order status",
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
            detail="Order not found",
        )

    order.status = status

    db.commit()

    db.refresh(order)

    return {

        "message":
            "Order Status Updated",

        "status":
            order.status,
    }


# =========================================================
# ADMIN - ALL RESERVATIONS
# =========================================================

@app.get("/admin/reservations")
def admin_reservations(

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db),
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

            "user_email":
                r.user_email,

            "name":
                r.name,

            "phone":
                r.phone,

            "guests":
                r.guests,

            "reservation_date":
                r.reservation_date,

            "reservation_time":
                r.reservation_time,

            "occasion":
                r.occasion,

            "table_type":
                r.table_type,

            "special_request":
                r.special_request,

            "status":
                r.status,
        }

        for r in reservations
    ]


# =========================================================
# ADMIN UPDATE RESERVATION STATUS
# =========================================================

@app.put(
    "/admin/reservations/{reservation_id}/status"
)
def update_reservation_status(

    reservation_id: int,

    status: str,

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db),
):

    allowed_statuses = [

        "Pending",

        "Confirmed",

        "Completed",

        "Cancelled",
    ]

    if status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid reservation status",
        )

    reservation = (

        db.query(modals.Reservation)

        .filter(
            modals.Reservation.id
            == reservation_id
        )

        .first()
    )

    if not reservation:

        raise HTTPException(
            status_code=404,
            detail="Reservation not found",
        )

    reservation.status = status

    db.commit()

    return {

        "message":
            "Reservation Status Updated",

        "status":
            reservation.status,
    }


# =========================================================
# USERS - ADMIN ONLY
# =========================================================

@app.get("/users")
def users(

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db),
):

    users = (
        db.query(modals.User)
        .all()
    )

    return [

        {

            "id":
                u.id,

            "name":
                u.name,

            "email":
                u.email,
        }

        for u in users
    ]


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.get("/admin/dashboard")
def dashboard(

    admin=Depends(get_current_admin),

    db: Session = Depends(get_db),
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
            modals.Order.payment_status
            == "Paid"
        )

        .all()
    )

    total_revenue = sum(

        order.grand_total or 0

        for order in paid_orders
    )

    return {

        "total_users":
            total_users,

        "total_orders":
            total_orders,

        "total_reservations":
            total_reservations,

        "revenue":
            total_revenue,
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def root():

    return {
        "message":
            "Savory Haven API is running"
    }
