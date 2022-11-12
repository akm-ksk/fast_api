from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from routers import rout_todo, rout_auth
from schema import SuccessMsg, CsrfSettings
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError

app = FastAPI()
app.include_router(rout_todo.router)
app.include_router(rout_auth.router)

# ホワイトリスト
origins = ['http://localhost:3000/']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # ホワイトリスト
    allow_credentials=True,  # クッキーの設定
    allow_methods=["*"],  # リクエストを許可するメソッド
    allow_headers=["*"]  # 許可するHTTPリクエストヘッダー
)


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})


@app.get('/', response_model=SuccessMsg)
def root():
    return {"message": "Welcome to Fast API"}
