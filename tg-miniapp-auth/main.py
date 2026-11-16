from fastapi import Depends, FastAPI
from auth import get_current_tg_user

app = FastAPI()


@app.get("/api/me")
def get_me(current_user: dict = Depends(get_current_tg_user)):
    return current_user
