from fastapi import APIRouter, HTTPException, Depends
from fastapi import Request, Response
from fastapi.encoders import jsonable_encoder
from starlette.status import HTTP_201_CREATED
from fastapi_csrf_protect import CsrfProtect
from typing import List

from database import db_create_todo, db_get_todos, db_get_single_todo, db_update_todo, db_delete_todo
from schema import Todo, TodoBody, SuccessMsg
from auth_utils import AuthJwtCsrf

router = APIRouter()
auth = AuthJwtCsrf()


# Todoを追加するエンドポイント
@router.post("/api/todo", response_model=Todo)
async def create_todo(request: Request, response: Response, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    # JTWトークンの更新
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)

    # dict型をJSONに変更
    todo = jsonable_encoder(data)

    res = await db_create_todo(todo)

    # 通常は200のレスポンスを201に変更
    response.status_code = HTTP_201_CREATED

    # クッキー更新
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_token}",
        httponly=True,
        samesite="none",
        secure=True
    )

    if res:
        return res
    raise HTTPException(status_code=404, detail="Create task failed")


# TodoのリストをGETするエンドポイント
@router.get("/api/todo", response_model=List[Todo])
async def get_todos(request: Request):
    # JWTの検証
    auth.verify_jwt(request)

    res = await db_get_todos()

    return res


# IDのTodoをGETするエンドポイント
@router.get("/api/todo/{todo_id}", response_model=Todo)
async def get_single_todo(request: Request, response: Response, todo_id: str):
    # JWTの検証と更新
    new_token, _ = auth.verify_update_jwt(request)

    res = await db_get_single_todo(todo_id)

    # クッキー更新
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_token}",
        httponly=True,
        samesite="none",
        secure=True
    )

    if res:
        return res

    raise HTTPException(status_code=404, detail={f"Task of ID : {todo_id} doesn't exist."})


# 指定したIDをのtodoをUpdateするエンドポイント
@router.put("/api/todo/{todo_id}", response_model=Todo)
async def update_todo(request: Request, response: Response, todo_id: str, data: dict,
                      csrf_protect: CsrfProtect = Depends()):
    # JTWトークンの更新
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)

    # dict型をJSONに変更
    todo = jsonable_encoder(data)
    res = await db_update_todo(todo_id, todo)

    # クッキー更新
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_token}",
        httponly=True,
        samesite="none",
        secure=True
    )

    if res:
        return res

    raise HTTPException(status_code=404, detail="Update task failed")


# 指定したIDをのtodoをDeleteするエンドポイント
@router.delete("/api/todo/{todo_id}", response_model=SuccessMsg)
async def delete_todo(request: Request, response: Response, todo_id: str, csrf_protect: CsrfProtect = Depends()):
    # JTWトークンの更新
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)

    res = await db_delete_todo(todo_id)

    # クッキー更新
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_token}",
        httponly=True,
        samesite="none",
        secure=True
    )

    if res:
        return {"message": "Successfully deleted"}

    raise HTTPException(status_code=404, detail="Delete task failed")
