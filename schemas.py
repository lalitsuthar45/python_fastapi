from typing import List, Optional
from pydantic import BaseModel


class UserCreate(BaseModel):
    name: str
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class GoogleLoginRequest(BaseModel):
    token: str


class UserUpdate(BaseModel):
    old_email: Optional[str] = None
    name: str
    email: str


class ChangePassword(BaseModel):
    email: str
    current_password: str
    new_password: str


class OrderItemCreate(BaseModel):
    food_name: str
    price: float
    quantity: int
    subtotal: float


class OrderCreate(BaseModel):
    user_email: str
    customer_name: str
    phone: str
    address: str
    city: str
    pincode: str
    payment_method: str
    upi_id: Optional[str] = None
    card_last4: Optional[str] = None
    payment_status: Optional[str] = "Pending"
    transaction_id: Optional[str] = None
    items_total: float
    gst: float
    delivery_charge: float
    discount: float
    grand_total: float
    items: List[OrderItemCreate]


class ReservationCreate(BaseModel):
    user_email: str
    name: str
    phone: str
    guests: int
    reservation_date: str
    reservation_time: str
    occasion: str
    table_type: str
    special_request: str