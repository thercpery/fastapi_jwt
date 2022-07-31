from fastapi import FastAPI, Depends, HTTPException, status
import fastapi.security as _security
import sqlalchemy.orm as _orm

from typing import List

import schemas as _schemas
import services as _services

app = FastAPI()
_services.create_database()


@app.post("/api/users")
async def create_user(user: _schemas.UserCreate, db: _orm.Session = Depends(_services.get_db)):
    is_email_exist = await _services.get_user_by_email(email=user.email, db=db)
    if is_email_exist:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use.")

    # Create user
    user = await _services.create_user(user=user, db=db)

    # Return JWT token
    return await _services.create_token(user=user)


@app.post("/api/users/login")
async def login_user(
        form_data: _security.OAuth2PasswordRequestForm = Depends(),
        db: _orm.Session = Depends(_services.get_db)):
    user = await _services.authenticate_user(email=form_data.username, password=form_data.password, db=db)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return await _services.create_token(user=user)


@app.get("/api/users/me", response_model=_schemas.User)
async def get_user(user: _schemas.User = Depends(_services.get_current_user)):
    return user


@app.post("/api/posts", response_model=_schemas.Post)
async def create_post(
        post: _schemas.PostCreate,
        user: _schemas.User = Depends(_services.get_current_user),
        db: _orm.Session = Depends(_services.get_db)):
    return await _services.create_post(user=user, db=db, post=post)


@app.get("/api/posts", response_model=List[_schemas.Post])
async def get_user_posts(
        user: _schemas.User = Depends(_services.get_current_user),
        db: _orm.Session = Depends(_services.get_db)):
    return await _services.get_user_posts(user=user, db=db)
