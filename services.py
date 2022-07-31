from fastapi import HTTPException, status, Depends
import fastapi.security as _security
import sqlalchemy.orm as _orm
import email_validator as _email_check
import passlib.hash as _hash
import jwt as _jwt
from dotenv import load_dotenv

import os as _os

import database as _database
import models as _models
import schemas as _schemas

load_dotenv()
_JWT_SECRET_KEY = _os.environ.get("JWT_SECRET_KEY")
oauth2schema = _security.OAuth2PasswordBearer("/api/users/login")


def create_database():
    return _database.Base.metadata.create_all(bind=_database.engine)


def get_db():
    db = _database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_user_by_email(email: str, db: _orm.Session):
    return db.query(_models.User).filter(_models.User.email == email).first()


async def create_user(user: _schemas.UserCreate, db: _orm.Session):
    # check if email is valid
    try:
        is_email_valid = _email_check.validate_email(email=user.email)
        email = is_email_valid.email

    except _email_check.EmailNotValidError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Please enter valid email")

    hash_password = _hash.bcrypt.hash(user.password)
    user_obj = _models.User(email=email, password=hash_password)

    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)

    return user_obj


async def create_token(user: _models.User):
    user_schema_obj = _schemas.User.from_orm(user)
    user_dict = user_schema_obj.dict()
    del user_dict["date_created"]

    token = _jwt.encode(user_dict, _JWT_SECRET_KEY)

    return dict(access_token=token, token_type="bearer")


async def authenticate_user(email: str, password: str, db: _orm.Session):
    user = await get_user_by_email(email=email, db=db)

    if not user:
        return False

    if not user.verify_password(password=password):
        return False

    return user


async def get_current_user(db: _orm.Session = Depends(get_db), token: str = Depends(oauth2schema)):
    try:
        payload = _jwt.decode(token, _JWT_SECRET_KEY, algorithms=["HS256"])
        user = db.query(_models.User).get(payload["id"])

    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not authorized. Please login first")

    return _schemas.User.from_orm(user)


async def create_post(user: _schemas.User, db: _orm.Session, post: _schemas.PostCreate):
    post = _models.Post(**post.dict(), owner_id=user.id)

    db.add(post)
    db.commit()
    db.refresh(post)

    return _schemas.Post.from_orm(post)


async def get_user_posts(user: _schemas.User, db: _orm.Session):
    posts = db.query(_models.Post).filter_by(owner_id=user.id)

    return list(map(_schemas.Post.from_orm, posts))
