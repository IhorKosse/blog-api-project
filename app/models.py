from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from .database import Base
from sqlalchemy.orm import relationship  # Add this line
class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    content = Column(String, index=True)
    comments = relationship("Comment", back_populates="post")
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    role = Column(String, default="user")
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    posts = relationship("Post", back_populates="author")
    comments = relationship("Comment", back_populates="user")
class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    post_id = Column(Integer, ForeignKey('posts.id'))

    user = relationship("User", back_populates="comments")
    post = relationship("Post", back_populates="comments")
