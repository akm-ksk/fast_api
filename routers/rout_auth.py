from fastapi import APIRouter, Response, Request, Depends
from fastapi.encoders import jsonable_encoder
from fastapi_csrf_protect import CsrfProtect

from auth_utils import AuthJwtCsrf
from schema import UserBody, UserInfo, SuccessMsg, Csrf
from database import db_signup, db_login

router = APIRouter()
auth = AuthJwtCsrf()


# CSRFトークンを生成するエンドポイント
@router.get("/api/csrftoken", response_model=Csrf)
def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    # CSRFトークンを取得
    csrf_token = csrf_protect.generate_csrf()
    res = {'csrf_token': csrf_token}

    return res

    return res


# 新規ユーザー登録エンドポイント
@router.post("/api/register", response_model=UserInfo)
async def signup(request: Request, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    # RequestヘッダーCSRFトークンを取得する
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)

    # csrf_tokenのバリデーション
    csrf_protect.validate_csrf(csrf_token)

    # JSONのエンコード
    user = jsonable_encoder(user)
    new_user = await db_signup(user)
    return new_user


# ログイン用エンドポイント
@router.post("/api/login", response_model=SuccessMsg)
async def login(request: Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    # RequestヘッダーCSRFトークンを取得する
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)

    # csrf_tokenのバリデーション
    csrf_protect.validate_csrf(csrf_token)

    # JSONのエンコード
    user = jsonable_encoder(user)

    # JWTトークン作成
    token = await db_login(user)

    # cookieセット
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        # クライアントからcookieの操作をさせない
        httponly=True,
        samesite="none",
        secure=True
    )

    return {"message": "Successfully logged-in"}


# ログアウト用のエンドポイント
@router.post("/api/logout", response_model=SuccessMsg)
def logout(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()):
    # RequestヘッダーCSRFトークンを取得する
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)

    # csrf_tokenのバリデーション
    csrf_protect.validate_csrf(csrf_token)

    # クッキーの更新
    response.set_cookie(
        key="access_token",
        value="",
        httponly=True,
        samesite="none",
        secure=True
    )

    return {"message": "Successfully logged-out"}


@router.get("/api/user", response_model=UserInfo)
def get_user_refresh_jwt(request: Request, response: Response):
    # 新しいJWTトークン , ユーザーのメールアドレス
    new_token, subject = auth.verify_update_jwt(request)

    # クッキー更新
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_token}",
        httponly=True,
        samesite="none",
        secure=True
    )

    return {'email': subject}
