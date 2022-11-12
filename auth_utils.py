import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
from decouple import config

JWT_KEY = config('JWT_KEY')


class AuthJwtCsrf:
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    # ユーザーの入力したパスワードをハッシュ化する
    def generate_hashed_pw(self, password) -> str:
        return self.pwd_ctx.hash(password)

    # 平文のパスワードとハッシュ化されたパスワードを比較する
    def verify_pw(self, plain_pw, hash_pw) -> bool:
        return self.pwd_ctx.verify(plain_pw, hash_pw)

    # JWTを生成する
    def encode_jwt(self, email) -> str:
        payload = {
            # JWTの有効期限(5分間)
            "exp": datetime.utcnow() + timedelta(days=0, minutes=5),
            'iat': datetime.utcnow(),
            # ユーザーを一意に識別できる値(ID,メール等)
            'sub': email
        }

        # JWTを生成
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm='HS256'
        )

    # JWTをデコードする
    def decode_jwt(self, token) -> (str, HTTPException):
        try:
            # デコード実行
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])

            return payload['sub']

        # JWTが執行している場合
        except jwt.ExpiredSignatureError:

            return HTTPException(status_code=401, detail="The JWT has expired")

        # JWTに準拠していないトークンやからの値を渡された場合のエラー
        except jwt.InvalidTokenError:

            return HTTPException(status_code=401, detail="JWT is not valid")

    # JWTトークンを検証するメソッド
    def verify_jwt(self, request) -> (str, HTTPException):

        # リクエストのクッキーを取得しJWTトークンを取得する
        token = request.cookies.get("access_token")
        if not token:
            return HTTPException(status_code=404, detail='No JWT exist : may not set yet or deleted')

        # tokenからJWTを取り出す
        _, _, value = token.partition(" ")

        # JWTの検証
        subject = self.decode_jwt(value)

        return subject

    # JWTの検証と更新 戻り値 更新されたJWTとサブジェクト
    def verify_update_jwt(self, request) -> tuple[str, str]:
        # JWTトークンを検証
        subject = self.verify_jwt(request)

        # 新しいJWTトークンの生成
        new_token = self.encode_jwt(subject)

        return new_token, subject

    # CSRFの検証 JWTの検証,JWTの更新
    def verify_csrf_update_jwt(self, request, csrf_protect, headers) -> str:

        # リクエストヘッダーの中からCSRFトークンを取り出す
        csrf_token = csrf_protect.get_csrf_from_header(headers)

        # CSRFをヴァリデートする
        csrf_protect.validate_csrf(csrf_token)

        # JWTの検証
        subject = self.verify_jwt(request)

        # 新しいJWTトークンの生成
        new_token = self.encode_jwt(subject)

        return new_token
