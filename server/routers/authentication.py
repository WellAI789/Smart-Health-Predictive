import os
import html
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone, UTC, date
from secrets import token_urlsafe

import jwt
import phonenumbers
import re
from email_validator import validate_email, EmailNotValidError
from fastapi import APIRouter, Depends, HTTPException, status, Request, \
    Response
from fastapi.responses import HTMLResponse
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pydantic import BaseModel
from fastapi_camelcase import CamelModel
from typing import Optional
from sqlalchemy.orm import Session
from html_sanitizer import Sanitizer

from ..utils.database import get_db
from ..models.dbmodels import UserAccount, UserAccountRole, \
    UserAccountValidationToken, AccountRole, LogEventType, Patient, \
    PasswordResetToken
from ..utils.email_service import send_email
from ..utils.audit_log import write_audit_log


EMAIL_VALIDATION_ENABLED = True
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
VALIDATION_TOKEN_LENGTH = 128
VALIDATION_EXPIRATION_IN_HOURS = 24
PASSWORD_MAX_LENGTH = 64
PASSWORD_MIN_LENGTH = 15
EMAIL_MAX_LENGTH = 255
NAME_MAX_LENGTH = 255
PHONE_MAX_LENGTH = 20
ACCOUNT_TYPE = {
    'user': 331928555,
    'merchant': 62809281
}
VALID_PASSWORD_SYMBOLS = "~!@#$%^&*()_+[]{}|:;,.?/"
MIN_AGE = 18

gender_map = {'Male': 1, 'Female': 0}


class UserRegistrationDetails(CamelModel):
    given_names: str
    family_name: str
    date_of_birth: Optional[date]
    gender: Optional[str]
    password: str
    email: str
    phone: str
    account_type: str
    clinic_id: Optional[int] = None


class LoginCredentials(BaseModel):
    email: str
    password: str


class TokenData(BaseModel):
    email: str
    ip_address: Optional[str] = None
    version: int


def _cookie_security_settings(request: Request):
    """Return cookie settings suitable for local development and HTTPS deployments."""
    is_https = request.url.scheme == 'https'
    if is_https:
        return {'secure': True, 'samesite': 'none'}
    return {'secure': False, 'samesite': 'lax'}


class ChangePasswordDetails(CamelModel):
    current_password: str
    new_password: str
    confirm_new_password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class PasswordResetRequest(BaseModel):
    token: str
    password: str


load_dotenv()

router = APIRouter()
owasp_argon2_hasher = Argon2Hasher(
    memory_cost=19456,  # 19 MiB
    time_cost=2,
    parallelism=1,
)
password_hasher = PasswordHash((owasp_argon2_hasher,))


@router.post("/register")
async def register(user_reg: UserRegistrationDetails,
                   db_conn: Session = Depends(get_db)):
    """
    Register a new user account after validating all input fields.

    Creates the user record, assigns a role, optionally creates a patient
    profile (standard users), and generates an email-validation token.

    :param user_reg: Registration details including personal info, credentials, and account type.
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A dict with a success message.
    :raises HTTPException 422: If any input field fails validation.
    """

    formatted_phone = format_phone_number(user_reg.phone)

    # Ensure user inputs are valid.
    if (not is_email_valid(user_reg.email) or
            not is_password_valid(user_reg.password) or
            not is_name_valid(user_reg.given_names) or
            not is_name_valid(user_reg.family_name) or
            not is_formatted_phone_valid(formatted_phone) or
            not is_role_valid(user_reg.account_type)):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if (user_reg.account_type == "user" and
        (not is_gender_valid(user_reg.gender) or
         not is_age_valid(user_reg.date_of_birth))):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    password_hash = password_hasher.hash(user_reg.password)

    # Ensure only merchant users have clinic ID's
    clinic_id = user_reg.clinic_id if user_reg.account_type == "merchant" else None

    new_user = UserAccount(
        clinicID=clinic_id,
        email=user_reg.email,
        password_hash=password_hash,
        phone_number=formatted_phone
    )
    if EMAIL_VALIDATION_ENABLED == False and user_reg.account_type == "user":
        new_user.IsValidated = True

    # Only add the user to the database of they don't exist.
    user = db_conn.query(UserAccount).filter_by(Email=user_reg.email).first()
    if not user:
        db_conn.add(new_user)

    # The user's ID is needed for to assign a role.
    new_user_id = db_conn.query(UserAccount.UserID). \
        filter_by(Email=user_reg.email).first()[0]
    role = UserAccountRole(ACCOUNT_TYPE[user_reg.account_type], new_user_id)

    # Create new patient record if they are a standard user.
    if user_reg.account_type == 'user':
        new_patient = Patient(
            user_id=new_user_id,
            given_names=user_reg.given_names,
            family_name=user_reg.family_name,
            gender=gender_map[user_reg.gender],
            date_of_birth=user_reg.date_of_birth,
            weight=0,
            height=0
        )
        db_conn.add(new_patient)

    # Require validation to confirm the user can access the email.
    validation_token = token_urlsafe(VALIDATION_TOKEN_LENGTH)
    expires_at = datetime.now(UTC) + \
        timedelta(hours=VALIDATION_EXPIRATION_IN_HOURS)
    acc_validation_token = UserAccountValidationToken(new_user_id,
                                                      validation_token,
                                                      expires_at)

    if not user:
        db_conn.add(role)
        db_conn.add(acc_validation_token)
        db_conn.commit()
        write_audit_log(db_conn,
                        eventType=LogEventType.REGISTRATION,
                        success=True,
                        userEmail=new_user.Email,
                        description="Successfully registered an account.")

        if EMAIL_VALIDATION_ENABLED:
            _send_validation_email(new_user, validation_token)
    else:
        db_conn.commit()

    return {'message': 'User successfully created.'}


def _send_validation_email(user: UserAccount, token: str):
    """Send a branded email-validation link to the newly registered user."""
    BACKEND_URL = os.getenv(
        "BACKEND_URL",
        "https://shp-backend.onrender.com"
    )

    validation_url = f"{BACKEND_URL}/validate-email?token={token}"

    logo_path = Path(__file__).resolve().parent.parent / "static" / "images" / "wellai-logo.png"

    email_subject = "Verify your WellAI account"

    email_content = f"""
    <html>
        <body style="
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            font-family: Arial, Helvetica, sans-serif;
        ">
            <div style="
                max-width: 600px;
                margin: 30px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            ">

                <!-- Header -->
                <div style="
                    background-color: #ffffff;
                    padding: 25px;
                    text-align: center;
                    border-bottom: 1px solid #eeeeee;
                ">
                    <img
                        src="cid:wellai-logo"
                        alt="WellAI"
                        style="
                            max-width: 220px;
                            width: 100%;
                            height: auto;
                        "
                    >
                </div>

                <!-- Content -->
                <div style="
                    padding: 35px 40px;
                    color: #333333;
                ">
                    <h1 style="
                        color: #6F2C91;
                        font-size: 24px;
                        margin-top: 0;
                    ">
                        Verify your WellAI account
                    </h1>

                    <p style="font-size: 16px; line-height: 1.6;">
                        Registration successful!
                    </p>

                    <p style="
                        font-size: 16px;
                        line-height: 1.6;
                    ">
                        Thank you for creating your WellAI account.
                        Please verify your email address to complete
                        your account setup.
                    </p>

                    <!-- Verification button -->
                    <div style="
                        text-align: center;
                        margin: 30px 0;
                    ">
                        <a
                            href="{validation_url}"
                            style="
                                display: inline-block;
                                padding: 14px 30px;
                                background-color: #6F2C91;
                                color: #ffffff;
                                text-decoration: none;
                                border-radius: 6px;
                                font-weight: bold;
                                font-size: 16px;
                            "
                        >
                            Verify my email
                        </a>
                    </div>

                    <p style="
                        font-size: 13px;
                        line-height: 1.5;
                        color: #666666;
                    ">
                        If you did not create a WellAI account,
                        you can safely ignore this email.
                    </p>

                    <p style="
                        font-size: 13px;
                        line-height: 1.5;
                        color: #666666;
                    ">
                        For your security, please do not forward this
                        email or share your verification link.
                    </p>
                </div>

                <!-- Footer -->
                <div style="
                    background-color: #f8f8f8;
                    padding: 20px;
                    text-align: center;
                    color: #777777;
                    font-size: 12px;
                ">
                    <p style="margin: 5px 0;">
                        Please do not reply to this email.
                    </p>

                    <p style="margin: 10px 0;">
                        <a
                            href="https://wellai.app/privacy-notice/"
                            style="
                                color: #6F2C91;
                                text-decoration: none;
                            "
                        >
                            Privacy Notice
                        </a>
                    </p>

                    <p style="margin: 5px 0;">
                        &copy; 2026 WellAI Sdn. Bhd. All rights reserved.
                    </p>
                </div>

            </div>
        </body>
    </html>
    """

    send_email(
        recipient=user.Email,
        subject=email_subject,
        content=email_content,
        content_type="html",
        inline_image_path=str(logo_path),
        inline_image_cid="wellai-logo"
    )


@router.get("/validate-email")
async def validate_email_address(token: str, db_conn: Session = Depends(get_db)):
    """Validate a user's email address via a signed token sent by email."""
    def validation_error_response():
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verification Link Invalid - WellAI</title>
            <style>
                body {
                    margin: 0;
                    padding: 40px 20px;
                    background-color: #f7f7f7;
                    font-family: Arial, Helvetica, sans-serif;
                    color: #333333;
                }

                .container {
                    max-width: 600px;
                    margin: 40px auto;
                    background-color: #ffffff;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
                }

                .header {
                    background-color: #702F8A;
                    padding: 30px 20px;
                    text-align: center;
                    color: #ffffff;
                }

                .brand {
                    font-size: 32px;
                    font-weight: bold;
                }

                .tagline {
                    margin-top: 6px;
                    font-size: 14px;
                }

                .content {
                    padding: 40px 35px;
                    text-align: center;
                }

                .error-icon {
                    width: 64px;
                    height: 64px;
                    margin: 0 auto 20px;
                    border-radius: 50%;
                    background-color: #702F8A;
                    color: #ffffff;
                    font-size: 32px;
                    line-height: 64px;
                    font-weight: bold;
                }

                h1 {
                    color: #702F8A;
                    font-size: 26px;
                    margin-bottom: 18px;
                }
                p {
                    font-size: 16px;
                    line-height: 1.6;
                    color: #555555;
                }

                .footer {
                    border-top: 1px solid #eeeeee;
                    background-color: #fafafa;
                    padding: 22px 20px;
                    text-align: center;
                    color: #777777;
                    font-size: 13px;
                }

                .footer a {
                    color: #702F8A;
                    text-decoration: none;
                }

                @media (max-width: 600px) {
                    body {
                        padding: 20px 10px;
                    }

                    .content {
                        padding: 30px 20px;
                    }

                    h1 {
                        font-size: 23px;
                    }
                }
            </style>
        </head>

        <body>
            <div class="container">

                <div class="header">
                    <div class="brand">WellAI</div>
                    <div class="tagline">Love Yourself</div>
                </div>

                <div class="content">
                    <div class="error-icon">&#33;</div>

                    <h1>Verification Link Invalid</h1>

                    <p>
                        This email verification link is no longer valid.
                        It may have expired or already been used.
                    </p>

                    <p>
                        Please request a new verification email to continue
                        setting up your WellAI account.
                    </p>
                </div>

                <div class="footer">
                    <p>
                        <a href="https://wellai.app/privacy-notice/" target="_blank">
                            Privacy Notice
                        </a>
                    </p>

                    <p>
                        &copy; 2026 WellAI Sdn. Bhd. All rights reserved.
                    </p>
                </div>

            </div>
        </body>
        </html>
        """

        return HTMLResponse(
            content=html_content,
            status_code=status.HTTP_400_BAD_REQUEST
        )

    # Find the token in the database
    validation_token_entry = db_conn.query(
        UserAccountValidationToken).filter_by(ValidationToken=token).first()

    # Check if the token exists
    if not validation_token_entry:
        return validation_error_response()

    # Check if the token has expired
    if validation_token_entry.ExpiresAt < datetime.utcnow():
        return validation_error_response()

    # Get the user associated with the token
    user = db_conn.query(UserAccount).filter_by(
        UserID=validation_token_entry.UserID).first()
    if not user:
        # This should not happen if database integrity is maintained
        return validation_error_response()

    # Update the user's validation status
    user.IsValidated = True

    # Optionally, delete the token after use
    db_conn.delete(validation_token_entry)

    db_conn.commit()

    write_audit_log(db_conn,
                    eventType=LogEventType.EMAIL_VALIDATION,
                    success=True,
                    userEmail=user.Email,
                    description=f"Email successfully validated.")

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verified - WellAI</title>
        <style>
            body {
                margin: 0;
                padding: 40px 20px;
                background-color: #f7f7f7;
                font-family: Arial, Helvetica, sans-serif;
                color: #333333;
            }

            .container {
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
            }

            .header {
                background-color: #702F8A;
                padding: 30px 20px;
                text-align: center;
                color: #ffffff;
            }

            .brand {
                font-size: 32px;
                font-weight: bold;
                margin: 0;
            }

            .tagline {
                margin: 6px 0 0;
                font-size: 14px;
                font-weight: 500;
            }

            .content {
                padding: 40px 35px;
                text-align: center;
            }

            .success-icon {
                width: 64px;
                height: 64px;
                margin: 0 auto 20px;
                border-radius: 50%;
                background-color: #702F8A;
                color: #ffffff;
                font-size: 36px;
                line-height: 64px;
                font-weight: bold;
            }

            h1 {
                margin: 0 0 18px;
                color: #702F8A;
                font-size: 28px;
            }

            p {
                margin: 10px 0;
                font-size: 16px;
                line-height: 1.6;
            }

            .message {
                color: #555555;
            }

            .footer {
                border-top: 1px solid #eeeeee;
                background-color: #fafafa;
                padding: 22px 20px;
                text-align: center;
                color: #777777;
                font-size: 13px;
            }

            .footer a {
                color: #702F8A;
                text-decoration: none;
            }

            .footer a:hover {
                text-decoration: underline;
            }

            @media (max-width: 600px) {
                body {
                    padding: 20px 10px;
                }

                .container {
                    margin: 20px auto;
                }

                .content {
                    padding: 30px 20px;
                }

                h1 {
                    font-size: 24px;
                }
            }
        </style>
    </head>

    <body>
        <div class="container">

            <div class="header">
                <div class="brand">WellAI</div>
                <div class="tagline">Love Yourself</div>
            </div>

            <div class="content">
                <div class="success-icon">&#10003;</div>

                <h1>Email Verified Successfully!</h1>

                <p class="message">
                    Your email address has been successfully verified.
                </p>

                <p class="message">
                    Your WellAI account is now ready. You can close this window
                    and return to the WellAI application to log in.
                </p>
            </div>

            <div class="footer">
                <p>
                    Please do not reply to this page.
                </p>

                <p>
                    <a href="https://wellai.app/privacy-notice/" target="_blank">
                        Privacy Notice
                    </a>
                </p>

                <p>
                    &copy; 2026 WellAI Sdn. Bhd. All rights reserved.
                </p>
            </div>

        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.post('/login')
async def login(request: Request, response: Response, user_cred: LoginCredentials,
                db_conn: Session = Depends(get_db)):
    """
    Authenticate a user and issue an http-only cookie with a JWT access token.

    Validates credentials, increments the token version (invalidating previous
    sessions), and sets the ``auth_token`` cookie on the response.

    :param request: The HTTP request (used for audit-logging client metadata).
    :param response: The HTTP response (used to set the cookie).
    :param user_cred: Login credentials (email and password).
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A dict with a success message.
    :raises HTTPException 401: If credentials are incorrect.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Incorrect username or password',
    )

    # Ensure user inputs are valid.
    if len(user_cred.password) < 1 or \
            not is_email_valid(user_cred.email):
        raise credentials_exception

    user = authenticate_user(user_cred.email, user_cred.password, db_conn)
    if not user:
        # Log failed login attempts.
        write_audit_log(db_conn,
                        eventType=LogEventType.FAILED_LOGIN_ATTEMPT,
                        success=False,
                        userEmail=user_cred.email,
                        device=request.headers.get("user-agent"),
                        ipAddress=request.client.host,
                        description="Login failed with incorrect credentials.")
        raise credentials_exception

    # Invalidate previous access token.
    user.TokenVersion += 1
    db_conn.commit()

    # Provide the user a new access token.
    expiration = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data = {
        'sub': user.Email,
        'version': user.TokenVersion
    }
    token = create_access_token(data, expiration)

    cookie_settings = _cookie_security_settings(request)

    # bearer:disable python_django_cookies
    response.set_cookie(
        key='auth_token',
        value=token,
        httponly=True,
        secure=cookie_settings['secure'],
        samesite=cookie_settings['samesite']
    )
    write_audit_log(db_conn,
                    eventType=LogEventType.LOGIN,
                    success=True,
                    userEmail=user.Email,
                    device=request.headers.get("user-agent"),
                    ipAddress=request.client.host,
                    description=f"Successful login attempt.")

    return {'message': 'Successfully logged in.'}


def authenticate_user(email: str, password: str, db_conn: Session):
    """
    Verify credentials and return the user account if authentication succeeds.

    Checks the user exists, is validated (if email validation is enabled),
    and the password matches the stored hash.

    :param email: The user's email address.
    :param password: The plain-text password to verify.
    :param db_conn: Database session.
    :return: The ``UserAccount`` object if authentication succeeds, ``False`` otherwise.
    """
    user = db_conn.query(UserAccount).filter_by(Email=email).first()
    if not user:
        return False

    if EMAIL_VALIDATION_ENABLED and not user.IsValidated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email address not verified. Please check your inbox to verify your email address."
        )

    if not verify_password(password, user.PasswordHash):
        return False
    return user


def verify_password(password_text: str, password_hash: str) -> bool:
    """Verifies a given password matches with a password hash."""
    return password_hasher.verify(password_text, password_hash)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Create a signed JWT access token containing the given claims.

    Encodes the data dict with an ``exp`` claim set to the current time plus
    the provided delta (or a default of 10 minutes).

    :param data: Claims to encode (must include ``sub`` for the subject).
    :param expires_delta: Optional custom expiration duration.
    :return: A signed JWT string.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=10)
    to_encode.update({'exp': expire})

    return jwt.encode(to_encode, os.environ['SECRET_KEY'], algorithm=ALGORITHM)


@router.get('/user/me')
async def get_user_me(request: Request, db_conn: Session = Depends(get_db)):
    """Return the currently authenticated user's profile information."""
    return get_current_user(request, db_conn)


def get_current_user(request: Request, db_conn: Session):
    """
    Extract and return the authenticated user's details from the http-only cookie.

    Decodes the JWT in the ``auth_token`` cookie, validates the token version
    against the database, and fetches the user's role and patient profile.

    :param request: The HTTP request containing the ``auth_token`` cookie.
    :param db_conn: Database session.
    :return: A dict with keys ``email``, ``role``, ``name``, ``phone_number``,
             ``given_names``, ``family_name``, ``gender``, ``weight``, ``height``,
             ``date_of_birth``.
    :raises HTTPException 401: If the token is missing, invalid, or expired.
    """

    # Prepare an exception for invalid or missing credentials.
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials'
    )

    token = request.cookies.get('auth_token')
    if token is None:
        raise credentials_exception

    # Extract the data from the jwt token.
    try:
        payload = jwt.decode(
            token, os.environ['SECRET_KEY'], algorithms=[ALGORITHM])
        token_data = TokenData(
            email=payload.get('sub'),
            version=payload.get('version')
        )
        if token_data.email is None:
            raise credentials_exception

    except InvalidTokenError as exc:
        raise credentials_exception from exc

    # Retrieve the user from the database
    user = get_user(token_data.email, db_conn)
    if not user.TokenVersion == token_data.version:
        raise credentials_exception

    if user is None:
        raise credentials_exception

     # Retrieve user role form the DB
    user_role = get_user_role(user.Email, db_conn)
    if user_role is None:
        raise credentials_exception

    patient_details = get_patient_by_email(user.Email, db_conn)

    return {
        'email': user.Email,
        'role': user_role,
        'name': patient_details.GivenNames if patient_details else user.Email.split('@')[0],
        'phone_number': user.PhoneNumber,
        'given_names': patient_details.GivenNames if patient_details else None,
        'family_name': patient_details.FamilyName if patient_details else None,
        'gender': patient_details.Gender if patient_details else None,
        'weight': float(patient_details.Weight) if patient_details and patient_details.Weight is not None else None,
        'height': float(patient_details.Height) if patient_details and patient_details.Height is not None else None,
        'date_of_birth': patient_details.DateOfBirth.isoformat() if patient_details and patient_details.DateOfBirth else None,
    }


def get_user(email: str, db_conn: Session):
    """Returns user account details from the database using an email."""
    return db_conn.query(UserAccount).filter_by(Email=email).first()


def get_patient_by_email(email: str, db_conn: Session):
    """Returns patient details from the database using an email."""
    patient = (
        db_conn.query(Patient)
        .join(UserAccount, Patient.UserID == UserAccount.UserID)
        .filter(UserAccount.Email == email)
        .first()
    )
    return patient


def get_user_role(email: str, db_conn: Session):
    """Returns the role for a given a user by email."""
    user_role = (db_conn.query(AccountRole.RoleName)
                 .join(UserAccountRole, UserAccountRole.RoleID == AccountRole.RoleID)
                 .join(UserAccount, UserAccount.UserID == UserAccountRole.UserID)
                 .filter(UserAccount.Email == email)
                 .first())
    return user_role[0]


@router.post('/logout')
def logout_current_user(request: Request, response: Response, db_conn: Session = Depends(get_db)):
    """
    Log out the current user by deleting the auth cookie and invalidating the token.

    Increments the token version in the database so existing JWTs are rejected,
    then removes the ``auth_token`` cookie from the response.

    :param request: The HTTP request (for current-user extraction).
    :param response: The HTTP response (for cookie deletion).
    :param db_conn: Database session.
    :return: ``None`` (cookie is deleted on the response object).
    """
    try:
        user = get_current_user(request, db_conn)
        if user:
            invalidate_access_token(user['email'], db_conn)
    except HTTPException:
        pass  # No valid cookie found
    finally:
        cookie_settings = _cookie_security_settings(request)
        
        response.delete_cookie(
            key='auth_token',
            httponly=True,
            secure=cookie_settings['secure'],
            samesite=cookie_settings['samesite'] 
        )


def invalidate_access_token(email: str, db_conn: Session):
    """Increase the user's token version number."""
    user = db_conn.query(UserAccount).filter_by(Email=email).first()
    user.TokenVersion += 1
    db_conn.commit()


def is_password_valid(password: str):
    """
    Verify a password meets all policy requirements.

    Rules: at least one lowercase, one uppercase, one digit, one symbol
    (from ``VALID_PASSWORD_SYMBOLS``), and length between ``PASSWORD_MIN_LENGTH``
    and ``PASSWORD_MAX_LENGTH``.

    :param password: The plain-text password to check.
    :return: ``True`` if the password complies with policy, ``False`` otherwise.
    """

    contains_lower = any(c.islower() for c in password)
    contains_upper = any(c.isupper() for c in password)
    contains_number = any(c.isnumeric() for c in password)
    contains_symbol = any(char in VALID_PASSWORD_SYMBOLS for char in password)
    valid_length = len(password) <= PASSWORD_MAX_LENGTH and \
        len(password) >= PASSWORD_MIN_LENGTH

    return contains_lower \
        and contains_upper \
        and contains_number \
        and contains_symbol \
        and valid_length


def is_email_valid(email: str):
    """Verifies an email follows the pattern xxx@xxx.xxx."""
    if not email:
        return False
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return False
    return len(email) < EMAIL_MAX_LENGTH


def format_phone_number(phone: str):
    """Removes everything but digits from a given phone number."""
    return ''.join(c for c in phone if c.isdigit())


def is_formatted_phone_valid(phone: str):
    """Verifies a phone number only containing digits a valid number
       or is empty."""
    if phone == '':
        return True

    # Only allow for numbers after the plus sign.
    if not phone.isdigit():
        return False
    try:
        phonenumbers.parse('+' + phone)
    except phonenumbers.NumberParseException:
        return False
    return True


def is_name_valid(name: str):
    """Verifies a name is valid."""
    return name is not None or len(name) <= NAME_MAX_LENGTH


def is_role_valid(role: str):
    """Verifies the role is valid for registration."""
    return role in ACCOUNT_TYPE.keys()


def is_gender_valid(gender: str):
    """Verifies gender is valid"""
    return gender in gender_map


def is_age_valid(date_of_birth: date):
    """Verifies age is valid and the user is at least 18"""
    today = date.today()
    year_diff = today.year - date_of_birth.year

    # checks if the persons birthday has happened this year
    birthday_not_passed = ((today.month, today.day) < (
        date_of_birth.month, date_of_birth.day))

    age = year_diff - birthday_not_passed
    return age >= MIN_AGE


@router.post('/change-password')
def change_password_current_user(password_details: ChangePasswordDetails, request: Request, db_conn: Session = Depends(get_db)):
    """
    Change the authenticated user's password after verifying their current password.

    Validates the current password, confirms the new password matches the
    confirmation field, then hashes and persists the new password.

    :param password_details: Object containing ``current_password``, ``new_password``,
                             and ``confirm_new_password``.
    :param request: The HTTP request (for current-user extraction and audit logging).
    :param db_conn: Database session.
    :return: A dict with a success message.
    :raises HTTPException 401: If current password is wrong or new passwords don't match.
    """

    # Retrieve current user data
    user_email = get_current_user(request, db_conn)
    user = get_user(user_email["email"], db_conn)

    # Check the password is correct
    if not verify_password(password_details.current_password, user.PasswordHash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    # Check the new password is confirmed correct
    if password_details.new_password != password_details.confirm_new_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    # Hash password
    new_password_hash = password_hasher.hash(
        password_details.new_password.encode('utf-8'))

    # Change current password to new password
    user.PasswordHash = new_password_hash
    db_conn.commit()
    write_audit_log(db_conn,
                    eventType=LogEventType.PASSWORD_CHANGE,
                    success=True,
                    userEmail=user_email["email"],
                    device=request.headers.get("user-agent"),
                    ipAddress=request.client.host,
                    description=f"Password successfully changed.")

    return {'message': 'User successfully changed password.'}


@router.post('/forgot-password')
def forgot_password(forgot_password_request: ForgotPasswordRequest, request: Request, db_conn: Session = Depends(get_db)):
    """
    Generate a password-reset token and email it to the user (if the account exists).

    Sanitises the email, looks up the user (excluding admin accounts), creates
    a time-limited reset token, and sends a reset link. Responds identically
    whether or not the email exists (to prevent enumeration).

    :param forgot_password_request: Object containing the user's email address.
    :param request: The HTTP request (for audit-logging client metadata).
    :param db_conn: Database session.
    :return: ``None`` (email is sent asynchronously).
    """
    is_success = False

    sanitised_email = re.sub(r'[()<>[\]:,;\\]', '',
                             forgot_password_request.email)
    if is_email_valid(sanitised_email):
        user = db_conn.query(UserAccount, AccountRole) \
            .filter(UserAccount.Email == sanitised_email) \
            .outerjoin(UserAccountRole, UserAccount.UserID == UserAccountRole.UserID) \
            .outerjoin(AccountRole, UserAccountRole.RoleID == AccountRole.RoleID) \
            .first()

        if user and user.AccountRole.RoleName != 'admin':
            patient = db_conn.query(Patient).filter_by(
                UserID=user.UserAccount.UserID).first()

            # Only allow one token to exist per user.
            existing_token = db_conn.query(
                PasswordResetToken).filter_by(UserID=user.UserAccount.UserID).first()
            if existing_token:
                db_conn.delete(existing_token)

            token = token_urlsafe(VALIDATION_TOKEN_LENGTH)
            expires_at = datetime.now() + timedelta(minutes=30)
            pass_reset_token = PasswordResetToken(
                user.UserAccount.UserID,
                token,
                expires_at
            )

            db_conn.add(pass_reset_token)
            db_conn.commit()
            is_success = True
            _send_reset_password_email(
                user.UserAccount, patient, request, token)

    write_audit_log(
        db_conn,
        eventType=LogEventType.RESET_PASSWORD_REQUEST,
        success=is_success,
        device=request.headers.get("user-agent"),
        ipAddress=request.client.host,
        description="Password reset requested for {}".format(sanitised_email)
    )


@router.post("/password-reset")
async def password_reset(
    reset_request: PasswordResetRequest,
    request: Request,
    db_conn: Session = Depends(get_db)
):
    """
    Reset a user's password using a valid, non-expired reset token.

    Validates the token, checks the new password against policy rules,
    hashes it, and persists the change. The token is consumed (deleted)
    regardless of success to prevent replay.

    :param reset_request: Object containing the reset token and new password.
    :param request: The HTTP request (for audit-logging client metadata).
    :param db_conn: Database session.
    :return: ``None`` (audit log is written on every attempt).
    """
    is_successful = False
    user = None

    token_entry = db_conn.query(
        PasswordResetToken).filter_by(Token=reset_request.token).first()
    if token_entry \
            and datetime.now(UTC) < token_entry.ExpiresAt.astimezone(timezone.utc):
        db_conn.delete(token_entry)
        db_conn.commit()

        user = db_conn.query(UserAccount) \
            .filter_by(UserID=token_entry.UserID) \
            .first()
        if is_password_valid(reset_request.password) and user:
            new_password_hash = password_hasher.hash(reset_request.password)
            user.PasswordHash = new_password_hash
            is_successful = True

    write_audit_log(
        db_conn,
        eventType=LogEventType.PASSWORD_RESET,
        success=is_successful,
        userID=None if user is None else user.UserID,
        userEmail=None if user is None else user.Email,
        device=request.headers.get("user-agent"),
        ipAddress=request.client.host,
        description="Attempt to reset password for account.",
    )


def _send_reset_password_email(
    user: UserAccount,
    patient: Patient,
    request: Request,
    token: str
):
    """
    Send a branded password-reset email containing a signed link.

    Sanitises all dynamic content before embedding it in the HTML email
    to prevent XSS in rendered email clients.

    :param user: The target user account.
    :param patient: The user's patient profile (for personalisation).
    :param request: The HTTP request (for client IP and user-agent).
    :param token: The unsigned reset token to embed in the link.
    """
    sanitizer = Sanitizer()

    sanitized_token = sanitizer.sanitize(token)
    given_names = sanitizer.sanitize(patient.GivenNames)
    family_name = sanitizer.sanitize(patient.FamilyName)
    ip_address = sanitizer.sanitize(request.client.host)
    device = sanitizer.sanitize(request.headers.get("user-agent"))

    frontend_url = os.getenv(
        "FRONTEND_URL",
        "https://smart-health-predictive.vercel.app"
    )

    reset_url = f"{frontend_url}/reset-password/{sanitized_token}"

    logo_path = (
        Path(__file__).resolve().parent.parent
        / "static"
        / "images"
        / "wellai-logo.png"
    )

    subject = "Reset your WellAI password"

    content = f"""
    <html>
        <body style="
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            font-family: Arial, Helvetica, sans-serif;
        ">
            <div style="
                max-width: 600px;
                margin: 30px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            ">

                <!-- Header -->
                <div style="
                    background-color: #ffffff;
                    padding: 25px;
                    text-align: center;
                    border-bottom: 1px solid #eeeeee;
                ">
                    <img
                        src="cid:wellai-logo"
                        alt="WellAI"
                        style="
                            max-width: 220px;
                            width: 100%;
                            height: auto;
                        "
                    >
                </div>

                <!-- Content -->
                <div style="
                    padding: 35px 40px;
                    color: #333333;
                ">
                    <h1 style="
                        color: #6F2C91;
                        font-size: 24px;
                        margin-top: 0;
                        margin-bottom: 20px;
                    ">
                        Reset Your Password
                    </h1>

                    <p style="
                        font-size: 16px;
                        line-height: 1.6;
                        margin: 0 0 15px 0;
                    ">
                        Hello {given_names} {family_name},
                    </p>

                    <p style="
                        font-size: 16px;
                        line-height: 1.6;
                        margin: 0 0 15px 0;
                    ">
                        We received a request to reset the password for
                        your WellAI Smart Health Predictive account.
                    </p>

                    <p style="
                        font-size: 16px;
                        line-height: 1.6;
                        margin: 0 0 10px 0;
                    ">
                        Click the button below to create a new password.
                    </p>

                    <!-- Reset button -->
                    <div style="
                        text-align: center;
                        margin: 30px 0;
                    ">
                        <a
                            href="{reset_url}"
                            style="
                                display: inline-block;
                                padding: 14px 30px;
                                background-color: #6F2C91;
                                color: #ffffff;
                                text-decoration: none;
                                border-radius: 6px;
                                font-weight: bold;
                                font-size: 16px;
                            "
                        >
                            Reset Password
                        </a>
                    </div>

                    <!-- Expiry notice -->
                    <div style="
                        background-color: #f8f4fa;
                        border-left: 4px solid #6F2C91;
                        padding: 14px 16px;
                        margin: 25px 0;
                    ">
                        <p style="
                            margin: 0;
                            font-size: 14px;
                            line-height: 1.5;
                            color: #555555;
                        ">
                            For your security, this password-reset link
                            will expire in <strong>30 minutes</strong>.
                        </p>
                    </div>

                    <!-- Security information -->
                    <h2 style="
                        color: #444444;
                        font-size: 16px;
                        margin: 25px 0 10px 0;
                    ">
                        Security Information
                    </h2>

                    <table style="
                        width: 100%;
                        border-collapse: collapse;
                        font-size: 14px;
                    ">
                        <tr>
                            <td style="
                                padding: 8px 0;
                                color: #666666;
                                width: 120px;
                            ">
                                IP Address
                            </td>
                            <td style="
                                padding: 8px 0;
                                color: #333333;
                            ">
                                {ip_address}
                            </td>
                        </tr>

                        <tr>
                            <td style="
                                padding: 8px 0;
                                color: #666666;
                                vertical-align: top;
                            ">
                                Device
                            </td>
                            <td style="
                                padding: 8px 0;
                                color: #333333;
                                word-break: break-word;
                            ">
                                {device}
                            </td>
                        </tr>
                    </table>

                    <p style="
                        font-size: 14px;
                        line-height: 1.6;
                        color: #666666;
                        margin-top: 25px;
                    ">
                        If you did not request a password reset, you can
                        safely ignore this email. Your password will not
                        be changed unless you complete the reset process.
                    </p>

                    <p style="
                        font-size: 14px;
                        line-height: 1.6;
                        color: #666666;
                    ">
                        For your security, please do not forward this email
                        or share your password-reset link with anyone.
                    </p>
                </div>

                <!-- Footer -->
                <div style="
                    background-color: #f8f8f8;
                    padding: 20px;
                    text-align: center;
                    color: #777777;
                    font-size: 12px;
                ">
                    <p style="margin: 5px 0;">
                        Please do not reply to this email.
                    </p>

                    <p style="margin: 10px 0;">
                        <a
                            href="https://wellai.app/privacy-notice/"
                            style="
                                color: #6F2C91;
                                text-decoration: none;
                            "
                        >
                            Privacy Notice
                        </a>
                    </p>

                    <p style="margin: 5px 0;">
                        &copy; 2026 WellAI Sdn. Bhd. All rights reserved.
                    </p>
                </div>

            </div>
        </body>
    </html>
    """

    send_email(
        recipient=user.Email,
        subject=subject,
        content=content,
        content_type="html",
        inline_image_path=str(logo_path),
        inline_image_cid="wellai-logo"
    )