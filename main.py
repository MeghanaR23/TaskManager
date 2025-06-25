from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
posts = []

class UserPost(BaseModel):
    name: str
    quote: str

@app.get("/posts")
async def read_root():
    print(str([post.model_dump() for post in posts]))

@app.post("/post")
async def create_post(post: UserPost):
    posts.append(post)
    print(str(post.model_dump()))  