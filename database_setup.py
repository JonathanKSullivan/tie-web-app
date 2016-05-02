import os
import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False, index=True)
    picture = Column(String(250), nullable=True)
    email = Column(String(250), nullable=False)
    password_hash = Column(String(64))


    def hash_password(self, password):
        return pwd_context.encrypt(password)


    def verify_password(self, password):

        return pwd_context.verify(password, self.password_hash)

    def __init__(self, name, email, picture, password):
        self.name = name
        self.email = email 
        self.picture = picture 
        self.password_hash = self.hash_password(password)
        
    def __repr__(self):
        return '<User %r>' % self.name

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'username': self.name,
            'email': self.email,
            
        }
class Event(Base):
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True)
    size = Column(Integer, nullable=True)
    date = Column(DateTime(timezone=True), nullable=False)
    topic = Column(String(150), nullable=False)
    details = Column(String(250), nullable=False)
    address = Column(String(250), nullable=False)
    city = Column(String(50), nullable=False)
    state = Column(String(2), nullable=False)
    zipcode = Column(String(5), nullable=False)
    cost = Column(Float(5), nullable=False)
    creation_date = Column(DateTime(timezone=True), nullable=False)
    creator = Column(Integer, ForeignKey('user.id'), nullable=True)
    user = relationship(User)
    
    def __init__(self, size, date, topic, details, address, city, state, zipcode, cost, user_id):
        self.size = size
        self.date = date
        self.topic = topic 
        self.details = details 
        self.address = address
        self.city = city 
        self.state = state 
        self.zipcode = zipcode
        self.cost = cost
        self.creation_date = datetime.datetime.today()
        self.creator = user_id

    def __repr__(self):
        return '<Event %r>' % self.topic

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'capacity': self.size,
            'date': self.date,
            'topic': self.topic,
            'details': self.details,
            'address': self.address,
            'city': self.city,
            'state': self.state,
            'zipcode': self.zipcode,
            'cost': self.cost,
            'creator_id': self.creator,
            'creation-date': self.creation_date
        }

class Correspondence(Base):
    __tablename__ = 'correspondence'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(250), nullable=False)
    country_code = Column(String(4), nullable=False)
    phone = Column(String(10), nullable=True)
    message = Column(String(5000), nullable=False)
    
    def __init__(self, first_name, last_name, email, country_code, phone, message):
        self.first_name = first_name
        self.last_name = last_name 
        self.email = email 
        self.country_code = country_code 
        self.phone = phone 
        self.message = message
    def __repr__(self):
        return '<Correspondence %r>' % self.first_name

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone': self.phone,
            'message': self.message,
        }

class Ticket(Base):
    __tablename__ = 'ticket'

    id = Column(Integer, primary_key=True)
    quantity = Column(Integer, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    user = relationship(User)
    event_id = Column(Integer, ForeignKey('events.id'), nullable=True)
    events = relationship(Event)
    pp_transaction = Column(String(200))

    def __init__(self, quantity, user_id, event_id, pp_transaction):
        self.quantity = quantity 
        self.user_id = user_id 
        self.event_id = event_id
        self.pp_transaction = pp_transaction
        
    def __repr__(self):
        return '<Ticket %r>' % self.id

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'quantity': self.quantity,
            'user_id': self.user_id,
            'event_id': self.event_id,
            'pp_transaction': self.pp_transaction
        }


class Testimonial(Base):
    __tablename__ = 'testimonial'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    headline = Column(String(50),  nullable=False)
    content = Column(String(1000), nullable=False)
    date = Column(DateTime(timezone=True), nullable=False)
    user = relationship(User)

    def __init__(self, headline, content, user_id):
        self.headline = headline
        self.content = content
        self.user_id = user_id
        self.date = datetime.datetime.today()


    def __repr__(self):
        return '<Testimonial %r>' % self.headline

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'image': self.image,
            'headline': self.headline,
            'content': self.content
        }
class Blog(Base):
    __tablename__ = 'blog'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    image = Column(String(250),  nullable=True)
    headline = Column(String(250),  nullable=False)
    hook =  Column(String(250),  nullable=True)
    content = Column(String(2000), nullable=False)
    user = relationship(User)

    def __init__(self, image, headline, hook, content, user_id):
        self.image = image 
        self.headline = headline
        self.hook = hook
        self.user_id = user_id
        self.content = content

    def __repr__(self):
        return '<Blog %r>' % self.headline

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'image': self.image,
            'headline': self.headline,
            'hook': self.hook,
            'content': self.content,
            'user': self.user
        }



class Log(Base):
    __tablename__ = 'log'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    activity = Column(String(250),  nullable=True)
    user = relationship(User)

    def __init__(self,  timestamp, user_id, activity):
        self.timestamp = timestamp 
        self.user_id = user_id
        self.activity = activity

    def __repr__(self):
        return '<Log %r>' % self.activity

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'user_id': self.user_id,
            'activity': self.activity,
        }

engine = create_engine('sqlite:///tiewebapp.db')
Base.metadata.create_all(engine)