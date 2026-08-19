from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100))
    email = Column(String(100), unique=True)
    password = Column(String(255))


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_email = Column(String(100))
    customer_name = Column(String(100))
    phone = Column(String(20))
    address = Column(String(255))
    city = Column(String(100))
    pincode = Column(String(20))
    payment_method = Column(String(50))
    upi_id = Column(String(100), nullable=True)
    card_last4 = Column(String(10), nullable=True)
    payment_status = Column(String(50), default="Pending")
    transaction_id = Column(String(100), nullable=True)
    items_total = Column(Float)
    gst = Column(Float)
    delivery_charge = Column(Float)
    discount = Column(Float)
    grand_total = Column(Float)
    status = Column(String(50), default="Pending")

    items = relationship("OrderItem", back_populates="order")


class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    order_id = Column(Integer, ForeignKey("orders.id"))
    food_name = Column(String(100))
    price = Column(Float)
    quantity = Column(Integer)
    subtotal = Column(Float)

    order = relationship("Order", back_populates="items")


class Reservation(Base):
    __tablename__ = "reservations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_email = Column(String(100))
    name = Column(String(100))
    phone = Column(String(20))
    guests = Column(Integer)
    reservation_date = Column(String(50))
    reservation_time = Column(String(50))
    occasion = Column(String(100))
    table_type = Column(String(100))
    special_request = Column(String(255))
    status = Column(String(50), default="Pending")