from decouple import config
from typing import Union
from bson import ObjectId
import motor.motor_asyncio
from fastapi import HTTPException

from auth_utils import AuthJwtCsrf

import asyncio

MONGO_API_KEY = config('MONGO_API_KEY')

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
client.get_io_loop = asyncio.get_event_loop

database = client.API_DB

collection_todo = database.todo
collection_user = database.user

auth = AuthJwtCsrf()


# FastAPIのfind_oneの返り値をdict型に変換する関数
def todo_serializer(todo) -> dict:
    return {
        "id": str(todo["_id"]),
        "title": todo["title"],
        "description": todo["description"],
    }


def user_serializer(user) -> dict:
    return {
        "id": str(user["_id"]),
        "email": user["email"],
    }


# DBにtodoを追加する関数
async def db_create_todo(data: dict) -> Union[dict, bool]:
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})

    if new_todo:
        return todo_serializer(new_todo)

    return False


# todoの一覧をGETする関数
async def db_get_todos() -> list:
    todos = []

    # todoリストを取得して一件ずつ変換してtodosに追加
    for todo in await collection_todo.find().to_list(length=100):
        todos.append(todo_serializer(todo))

    return todos


# todoIDを指定して取得
async def db_get_single_todo(todo_id: str) -> Union[dict, bool]:
    todo = await collection_todo.find_one({"_id": ObjectId(todo_id)})
    if todo:
        return todo_serializer(todo)
    return False


# todoIDを指定してUPDATE
async def db_update_todo(todo_id: str, data: dict) -> Union[dict, bool]:
    # 指定したIDのtodoがあるか確認する
    todo = await collection_todo.find_one({"_id": ObjectId(todo_id)})

    if todo:
        update_todo = await collection_todo.update_one(
            {"_id": ObjectId(todo_id)},
            {"$set": data}
        )

        # update_todo の modified_count (更新に成功した件数)が1以上なら更新データを取得
        if update_todo.modified_count > 0:
            new_todo = await collection_todo.find_one({"_id": ObjectId(todo_id)})
            return todo_serializer(new_todo)

    return False


# todoIDを指定して削除
async def db_delete_todo(todo_id: str) -> bool:
    # 指定したIDのtodoがあるか確認する
    todo = await collection_todo.find_one({"_id": ObjectId(todo_id)})

    if todo:
        delete_todo = await collection_todo.delete_one({"_id": ObjectId(todo_id)})

        # update_todo の modified_count (更新に成功した件数)が1以上なら更新データを取得
        if delete_todo.deleted_count > 0:
            return True

    return False


# 新規ユーザー登録
async def db_signup(data: dict) -> dict:
    # ユーザーが入力したメールアドレスとパスワードを取得
    email = data.get("email")
    password = data.get("password")
    overlap_user = await collection_user.find_one({"email": email})

    # 入力されたメールアドレスを使用しているユーザーが存在する
    if overlap_user:
        raise HTTPException(status_code=400, detail="Email is already taken")

    # パスワードのバリデーション
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")

    # ユーザーを追加する
    user = await collection_user.insert_one(
        {
            "email": email,
            "password": auth.generate_hashed_pw(password)
        }
    )

    # 追加したユーザーを取得
    new_user = await collection_user.find_one({"_id": user.inserted_id})

    return user_serializer(new_user)


# ログイン
async def db_login(data: dict) -> str:
    # ユーザーが入力したメールアドレスとパスワードを取得
    email = data.get("email")
    password = data.get("password")

    user = await collection_user.find_one({"email": email})

    # ユーザーとパスワードのチェック
    if not user or not auth.verify_pw(password, user["password"]):
        raise HTTPException(status_code=404, detail="Invalid email or password")

    # JWTトークンを生成する
    token = auth.encode_jwt(user["email"])

    return token
