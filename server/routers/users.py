import os
from pathlib import Path
from datetime import datetime, date, timedelta, timezone, UTC
from decimal import Decimal
from typing import List, Optional
from secrets import token_urlsafe

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from fastapi_camelcase import CamelModel
from sqlalchemy.orm import Session
from html_sanitizer import Sanitizer
import re
from sqlalchemy import func

from ..utils.database import get_db
from ..utils.audit_log import write_audit_log
from ..models.dbmodels import (
    UserAccount,
    UserAccountRole,
    UserAccountValidationToken,
    HealthData,
    Prediction,
    Recommendation,
    LogEventType,
    Patient,
    UserPatientAccess,
    Clinic,
    PatientRequestToken
)
from ..routers.authentication import get_current_user, get_user, get_patient_by_email, format_phone_number, is_formatted_phone_valid, is_email_valid, authenticate_user, send_email

NAME_MAX_LENGTH = 255
MIN_AGE = 18
VALIDATION_TOKEN_LENGTH = 128
gender_map = {'Male': 1, 'Female': 0}


class HealthMetric(CamelModel):
    # ISO datetime string of the prediction creation time
    date: str
    month: str
    stroke_probability: float
    cardio_probability: float
    diabetes_probability: float


class Report(CamelModel):
    patient_name: Optional[str] = None
    age: int
    weight: float
    height: float
    gender: int
    blood_glucose: float
    ap_hi: float
    ap_lo: float
    high_cholesterol: int
    hypertension: int
    heart_disease: int
    diabetes: int
    alcohol: int
    smoker: int
    marital_status: int
    working_status: int
    stroke_chance: float
    CVD_chance: float
    diabetes_chance: float
    race: int
    # Optional recommendations
    exercise_recommendation: Optional[str] = None
    diet_recommendation: Optional[str] = None
    lifestyle_recommendation: Optional[str] = None
    diet_to_avoid_recommendation: Optional[str] = None


class HealthDataDates(CamelModel):
    health_data_id: int
    date: datetime


class ClinicDetails(CamelModel):
    clinic_id: int
    clinic_name: str


class Dashboard(BaseModel):
    days: int
    risks: dict
    diff: dict
    recommendations: dict


class MerchantDashboard(CamelModel):
    total_patients: int
    total_reports: int
    reports_last_30_days: int
    inactive_patients: int
    risk_distribution: dict
    report_activity: List[dict]


class UserProfileUpdate(BaseModel):
    phone_number: Optional[str] = None


class PatientProfileUpdate(CamelModel):
    given_names: Optional[str] = None
    family_name: Optional[str] = None
    gender: Optional[int] = None
    weight: Optional[float] = None
    height: Optional[float] = None
    date_of_birth: Optional[date] = None


class PatientCreationDetails(CamelModel):
    given_names: str
    family_name: str
    date_of_birth: date
    gender: str
    weight: float
    height: float


class PatientDetails(CamelModel):
    patient_info: dict
    days: int
    risks: dict
    diff: dict
    recommendations: dict


class PatientRequest(BaseModel):
    email: str


class PatientAcceptDetails(BaseModel):
    token: str


def _to_float(val) -> float:
    """Safely convert a value to float, returning 0.0 on failure."""
    if isinstance(val, Decimal):
        return float(val)
    try:
        return float(val)
    except Exception:
        return 0.0


router = APIRouter()


def _validated_name(value: Optional[str], field_name: str) -> Optional[str]:
    """Sanitise and validate a name field; raises 422 if longer than 255 chars."""
    if value is None:
        return None
    sanitizer = Sanitizer()
    cleaned = sanitizer.sanitize(value).strip()
    if len(cleaned) > 255:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field_name} is too long.",
        )
    return cleaned


def _to_nullable_float(value: Optional[float], field_name: str, min_v: float, max_v: float) -> Optional[float]:
    """Validate and return a nullable float within [min_v, max_v]; raises 422 if out of range."""
    if value is None:
        return None
    if value < min_v or value > max_v:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field_name} must be between {min_v} and {max_v}.",
        )
    return float(value)


@router.patch("/users/me")
async def update_current_user_profile(
    payload: UserProfileUpdate,
    request: Request,
    db_conn: Session = Depends(get_db),
):
    """
    Update the authenticated user's account-level profile fields.

    Currently supports updating the ``phone_number`` field. The phone is
    formatted and validated before persisting.

    :param payload: Object containing the fields to update (only ``phone_number`` supported).
    :param request: The HTTP request (for audit-logging client metadata).
    :param db_conn: Database session.
    :return: A dict with a success message and the updated fields.
    :raises HTTPException 404: If the user is not found.
    :raises HTTPException 400: If no fields are provided for update.
    :raises HTTPException 422: If the phone number is invalid.
    """
    current_user = get_current_user(request, db_conn)
    user = get_user(current_user["email"], db_conn)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    updates = payload.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    updated_fields = {}
    if "phone_number" in updates:
        formatted_phone = format_phone_number(
            updates.get("phone_number") or "")
        if not is_formatted_phone_valid(formatted_phone):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid phone number",
            )
        user.PhoneNumber = formatted_phone
        updated_fields["phone_number"] = formatted_phone

    db_conn.commit()
    write_audit_log(
        db_conn,
        eventType=LogEventType.USER_PROFILE_UPDATED,
        success=True,
        userEmail=user.Email,
        device=request.headers.get("user-agent"),
        ipAddress=request.client.host if request.client else None,
        description="User updated account profile fields.",
    )

    return {"message": "Account details updated successfully", "updated": updated_fields}


@router.patch("/patients/me")
async def update_current_patient_profile(
    payload: PatientProfileUpdate,
    request: Request,
    db_conn: Session = Depends(get_db),
):
    """
    Update the authenticated user's patient profile fields.

    Supports updating ``given_names``, ``family_name``, ``gender``, ``weight``,
    ``height``, and ``date_of_birth``. Creates a patient record if one does
    not already exist.

    :param payload: Object containing the fields to update.
    :param request: The HTTP request (for audit-logging client metadata).
    :param db_conn: Database session.
    :return: A dict with a success message and the updated fields.
    :raises HTTPException 404: If the user is not found.
    :raises HTTPException 400: If no fields are provided for update.
    :raises HTTPException 422: If any field fails validation.
    """
    current_user = get_current_user(request, db_conn)
    user = get_user(current_user["email"], db_conn)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    updates = payload.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    patient = get_patient_by_email(user.Email, db_conn)
    if patient is None:
        patient = Patient(
            user_id=user.UserID,
            given_names=user.Email.split("@")[0],
            family_name="",
            gender=None,
            weight=0,
            height=0,
            date_of_birth=None,
        )
        db_conn.add(patient)
        db_conn.flush()

    updated_fields = {}
    if "given_names" in updates:
        patient.GivenNames = _validated_name(
            updates.get("given_names"), "given_names")
        updated_fields["given_names"] = patient.GivenNames
    if "family_name" in updates:
        patient.FamilyName = _validated_name(
            updates.get("family_name"), "family_name")
        updated_fields["family_name"] = patient.FamilyName
    if "gender" in updates:
        gender = updates.get("gender")
        if gender is not None and gender not in (0, 1):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="gender must be 0 (Female) or 1 (Male)",
            )
        patient.Gender = gender
        updated_fields["gender"] = patient.Gender
    if "weight" in updates:
        patient.Weight = _to_nullable_float(
            updates.get("weight"), "weight", 20.0, 300.0)
        updated_fields["weight"] = float(
            patient.Weight) if patient.Weight is not None else None
    if "height" in updates:
        patient.Height = _to_nullable_float(
            updates.get("height"), "height", 90.0, 250.0)
        updated_fields["height"] = float(
            patient.Height) if patient.Height is not None else None
    if "date_of_birth" in updates:
        date_of_birth = updates.get("date_of_birth")
        if date_of_birth and date_of_birth > date.today():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="date_of_birth cannot be in the future",
            )
        patient.DateOfBirth = date_of_birth
        updated_fields["date_of_birth"] = patient.DateOfBirth.isoformat(
        ) if patient.DateOfBirth else None

    db_conn.commit()
    write_audit_log(
        db_conn,
        eventType=LogEventType.PATIENT_PROFILE_UPDATED,
        success=True,
        userEmail=user.Email,
        device=request.headers.get("user-agent"),
        ipAddress=request.client.host if request.client else None,
        description="User updated patient profile fields.",
    )

    return {"message": "Profile updated successfully", "updated": updated_fields}


def _delete_user_data(user_id: int, db_conn: Session):
    """
    Delete a user and all associated data (cascading), returning a deletion report.

    Removes patient access links, recommendations, predictions, health data,
    validation tokens, and role mappings in the correct order to avoid
    foreign-key violations. Rolls back on failure.

    :param user_id: The ``UserID`` of the account to delete.
    :param db_conn: Database session.
    :return: A dict with counts of deleted records per table.
    :raises HTTPException 404: If the user is not found.
    :raises HTTPException 500: If the deletion fails.
    """
    deletion_report = {}

    try:
        # Find the user to ensure they exist before proceeding
        user_to_delete = db_conn.query(UserAccount).filter(
            UserAccount.UserID == user_id).first()
        if not user_to_delete:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        # Get patient record if it exists
        patient_record = get_patient_by_email(user_to_delete.Email, db_conn)

        # Delete Merchant Patient access
        if patient_record:
            db_conn.query(UserPatientAccess).filter(UserPatientAccess.PatientID ==
                                                    patient_record.PatientID).delete(synchronize_session=False)
        else:
            db_conn.query(UserPatientAccess).filter(
                UserPatientAccess.UserID == user_to_delete.UserID).delete(synchronize_session=False)

        # Collect all HealthDataIDs for this user
        health_ids: List[int] = [
            hid for (hid,) in db_conn.query(HealthData.HealthDataID).filter(HealthData.PatientID == patient_record.PatientID).all()
        ]

        if health_ids:
            # Delete tables that depend on HealthData first
            recs_deleted = db_conn.query(Recommendation).filter(
                Recommendation.HealthDataID.in_(health_ids)).delete(synchronize_session=False)
            deletion_report['recommendations_deleted'] = recs_deleted

            preds_deleted = db_conn.query(Prediction).filter(
                Prediction.HealthDataID.in_(health_ids)).delete(synchronize_session=False)
            deletion_report['predictions_deleted'] = preds_deleted

            # Then delete HealthData records
            health_data_deleted = db_conn.query(HealthData).filter(
                HealthData.PatientID == patient_record.PatientID).delete(synchronize_session=False)
            deletion_report['health_data_deleted'] = health_data_deleted

        # Delete tables directly associated with the user
        tokens_deleted = db_conn.query(UserAccountValidationToken).filter(
            UserAccountValidationToken.UserID == user_id).delete(synchronize_session=False)
        deletion_report['validation_tokens_deleted'] = tokens_deleted

        roles_deleted = db_conn.query(UserAccountRole).filter(
            UserAccountRole.UserID == user_id).delete(synchronize_session=False)
        deletion_report['user_roles_deleted'] = roles_deleted

        # Delete the user record itself
        db_conn.delete(user_to_delete)
        deletion_report['users_deleted'] = 1  # Since we are deleting one user

        db_conn.commit()
        return deletion_report
    except Exception as e:
        db_conn.rollback()
        # Log the exception e for debugging if needed
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to delete user data: {str(e)}")


@router.delete("/users/")
async def delete_user(request: Request, db_conn: Session = Depends(get_db)):
    """
    Delete the authenticated user's account and all associated data.

    Cascades to remove patient access links, health data, predictions,
    recommendations, validation tokens, and role mappings.

    :param request: The HTTP request (for current-user extraction and audit logging).
    :param db_conn: Database session.
    :return: A dict with a success message.
    :raises HTTPException 401: If credentials are invalid.
    :raises HTTPException 404: If the user is not found.
    """
    # Current request user
    current = get_current_user(request, db_conn)
    request_user_email = current.get(
        'email') if isinstance(current, dict) else None
    if not isinstance(request_user_email, str) or request_user_email.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user_to_delete = get_user(request_user_email, db_conn)
    if user_to_delete is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user_id = user_to_delete.UserID

    # Perform the deletion
    _delete_user_data(user_id, db_conn)
    write_audit_log(db_conn,
                    eventType=LogEventType.ACCOUNT_DELETED,
                    success=True,
                    userEmail=user_to_delete.Email,
                    device=request.headers.get("user-agent"),
                    ipAddress=request.client.host,
                    description=f"Account deleted from database.")

    return {"message": "User and all related data deleted successfully"}

# Health analytics


@router.get("/health-analytics", response_model=List[HealthMetric])
async def get_health_analytics(
    request: Request,
    db_conn: Session = Depends(get_db),
    health_data_id: Optional[int] = None,
):
    """Return time-series health risk probabilities from the current user's historical predictions."""
    user_email = get_current_user(request, db_conn)
    patient = get_patient_by_email(user_email["email"], db_conn)

    if not health_data_id:
        if not patient:
            return []
        patient_id = patient.PatientID

    else:
        # Retrieve patientID from selected health report.
        health_data = db_conn.query(HealthData).filter(
            HealthData.HealthDataID == health_data_id).first()
        if not health_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Health data not found.")

        patient_id = health_data.PatientID

        # Verify Merchant has access to patient.
        merchant = db_conn.query(UserAccount).filter_by(
            Email=user_email["email"]).first()
        merchant_access = (db_conn.query(UserPatientAccess)
                           .filter(UserPatientAccess.UserID == merchant.UserID, UserPatientAccess.PatientID == patient_id)
                           .first())

        if not merchant_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

    # Join predictions with health data to scope by user, order by prediction time
    rows = (
        db_conn.query(
            getattr(Prediction, 'CreatedAt'),
            getattr(Prediction, 'StrokeChance'),
            getattr(Prediction, 'CVDChance'),
            getattr(Prediction, 'DiabetesChance'),
        )
        .join(
            HealthData,
            getattr(Prediction, 'HealthDataID') == getattr(
                HealthData, 'HealthDataID'),
        )
        .filter(getattr(HealthData, 'PatientID') == patient_id)
        .order_by(getattr(Prediction, 'CreatedAt').asc())
        .all()
    )

    def month_label(dt: datetime) -> str:
        # e.g., 'Jan 2025' to help distinguish years if data spans multiple years
        try:
            return dt.strftime("%b %Y")
        except Exception:
            return str(dt)

    data: List[HealthMetric] = []
    for created_at, stroke, cvd, diab in rows:
        data.append(
            HealthMetric(
                date=(created_at.isoformat() if isinstance(
                    created_at, datetime) else str(created_at)),
                month=month_label(created_at),
                stroke_probability=_to_float(stroke),
                cardio_probability=_to_float(cvd),
                diabetes_probability=_to_float(diab),
            )
        )

    return data

# Report Data


@router.get("/report-data/{healthDataId}")
async def get_report_data(healthDataId: int, db_conn: Session = Depends(get_db)):
    """
    Return a full health report (metrics, predictions, recommendations) by health-data ID.

    :param healthDataId: The primary key of the ``HealthData`` record.
    :param db_conn: Database session.
    :return: A ``Report`` object containing patient info, vitals, risk probabilities,
             and AI recommendations.
    :raises HTTPException 404: If the health data is not found.
    """
    validID = db_conn.query(HealthData).filter_by(
        HealthDataID=healthDataId).first()
    if not validID:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report data not found")

    # Retrieve user health data
    healthData = db_conn.query(HealthData).filter(
        getattr(HealthData, 'HealthDataID') == healthDataId).first()
    predictionData = db_conn.query(Prediction).filter(
        getattr(Prediction, 'HealthDataID') == healthDataId).first()
    recommendationData = db_conn.query(Recommendation).filter(getattr(
        Recommendation, 'HealthDataID') == healthDataId).order_by(getattr(Recommendation, 'CreatedAt').desc()).first()

    patientData = db_conn.query(Patient).filter(
        Patient.PatientID == healthData.PatientID).first()
    if patientData:
        patient_name = f"{(patientData.GivenNames or '').strip()} {(patientData.FamilyName or '').strip()}".strip(
        ) or None
    else:
        patient_name = None

    # Create health report data to return
    reportData = Report(
        patientName=patient_name,
        age=int(getattr(healthData, 'Age', 0) or 0),
        weight=float(getattr(healthData, 'WeightKilograms', 0) or 0),
        height=float(getattr(healthData, 'HeightCentimetres', 0) or 0),
        gender=int(
            1 if bool(getattr(healthData, 'Gender', False) or False) else 0),
        blood_glucose=float(getattr(healthData, 'BloodGlucose', 0) or 0),
        ap_hi=float(getattr(healthData, 'APHigh', 0) or 0),
        ap_lo=float(getattr(healthData, 'APLow', 0) or 0),
        high_cholesterol=int(
            1 if bool(getattr(healthData, 'HighCholesterol', False) or False) else 0),
        hypertension=int(
            1 if bool(getattr(healthData, 'HyperTension', False) or False) else 0),
        heart_disease=int(
            1 if bool(getattr(healthData, 'HeartDisease', False) or False) else 0),
        diabetes=int(
            1 if bool(getattr(healthData, 'Diabetes', False) or False) else 0),
        alcohol=int(getattr(healthData, 'Alcohol', 0) or 0),
        smoker=int(getattr(healthData, 'SmokingStatus', 0) or 0),
        marital_status=int(getattr(healthData, 'MaritalStatus', 0) or 0),
        working_status=int(getattr(healthData, 'WorkingStatus', 0) or 0),
        race=int(getattr(healthData, 'Race', 0) or 0),
        stroke_chance=float(getattr(predictionData, 'StrokeChance', 0) or 0),
        CVD_chance=float(getattr(predictionData, 'CVDChance', 0) or 0),
        diabetes_chance=float(
            getattr(predictionData, 'DiabetesChance', 0) or 0),
        exercise_recommendation=getattr(
            recommendationData, 'ExerciseRecommendation', None) if recommendationData else None,
        diet_recommendation=getattr(
            recommendationData, 'DietRecommendation', None) if recommendationData else None,
        lifestyle_recommendation=getattr(
            recommendationData, 'LifestyleRecommendation', None) if recommendationData else None,
        diet_to_avoid_recommendation=getattr(
            recommendationData, 'DietToAvoidRecommendation', None) if recommendationData else None,
    )

    # Return reportData object
    return reportData


@router.delete("/report-data/{healthDataId}")
async def delete_report_data(healthDataId: int, db_conn: Session = Depends(get_db)):
    """
    Delete a health report and its associated predictions and recommendations.

    Removes the recommendation and prediction records first to avoid foreign-key
    violations, then deletes the health-data row itself.

    :param healthDataId: The primary key of the ``HealthData`` record to delete.
    :param db_conn: Database session.
    :return: A dict with a success message.
    :raises HTTPException 404: If the health data is not found.
    :raises HTTPException 500: If the database deletion fails.
    """
   # Raise exception if health data is not in the DB
    health_data = db_conn.query(HealthData).filter_by(
        HealthDataID=healthDataId).first()
    if not health_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Health report not found")

    try:
        # Delete recommendation and prediction data first to avoid a foreign key error
        db_conn.query(Recommendation).filter(getattr(
            Recommendation, 'HealthDataID') == healthDataId).delete(synchronize_session=False)
        db_conn.query(Prediction).filter(getattr(
            Prediction, 'HealthDataID') == healthDataId).delete(synchronize_session=False)
        # Delete health data
        db_conn.query(HealthData).filter(getattr(
            HealthData, 'HealthDataID') == healthDataId).delete(synchronize_session=False)

        db_conn.commit()
    except Exception:
        db_conn.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to delete health data.")

    return {"message": "Health report data successfully deleted"}


@router.get("/merchants/reports")
async def get_merchant_reports(request: Request, db_conn: Session = Depends(get_db)):
    """Retrieves all reports a merchant can view"""
    # Check if the requesting user is a merchant.
    merchant = get_current_merchant(request, db_conn)

    # Get patients associated with the merchant.
    patients = get_merchant_patients(merchant.UserID, db_conn)
    patient_ids = [p.PatientID for p in patients]
    # Get patient health data.
    patient_health_data = (db_conn.query(HealthData).filter(HealthData.PatientID.in_(patient_ids))
                           .order_by(HealthData.CreatedAt.desc()).all())
    result = []
    for row in patient_health_data:

        # Get the patient's name.
        patient = db_conn.query(Patient).filter_by(
            PatientID=row.PatientID).first()

        result.append({
            "name": f'{patient.GivenNames} {patient.FamilyName}',
            "healthDataId": row.HealthDataID,
            "date": row.CreatedAt
        })

    return result


@router.get("/merchants/patient-names")
async def get_patient_names(request: Request, db_conn: Session = Depends(get_db)):
    """Retrieves patients names that are associated with the a merchant"""
    # Check if the requesting user is a merchant.
    merchant = get_current_merchant(request, db_conn)

    # Get patient data associated with the merchant.
    patients = get_merchant_patients(merchant.UserID, db_conn)

    result = []
    existing_patient = set()
    for patient in patients:

        # Get the patient's name.
        if patient.PatientID not in existing_patient:
            result.append({
                "name": f'{patient.GivenNames} {patient.FamilyName}',
                "patientId": patient.PatientID
            })
            existing_patient.add(patient.PatientID)

    return result


@router.get("/get-health-data-dates/")
async def get_health_data(request: Request, db_conn: Session = Depends(get_db)):
    """Return the dates for all health reports"""
    # Retrieve user current user information
    user_email = get_current_user(request, db_conn)
    patient = get_patient_by_email(user_email["email"], db_conn)

    # Retrieve user health data
    healthData = db_conn.query(HealthData).filter(
        HealthData.PatientID == patient.PatientID).order_by(HealthData.CreatedAt.desc()).all()

    # Filter by ID and date create to return
    healthDataDates = [HealthDataDates(
        health_data_id=data.HealthDataID, date=data.CreatedAt) for data in healthData]

    return healthDataDates


@router.get("/get-clinic-names/")
async def get_clinic_names(request: Request, db_conn: Session = Depends(get_db)):
    """Returns the name of all stored clinics"""

    # Retrieve the all clinics
    clinics = (
        db_conn.query(Clinic)
        .order_by(Clinic.ClinicID.asc())
        .all()
    )
    # Filter clinic by name and id
    clinic_details = [
        ClinicDetails(clinic_id=clinic.ClinicID, clinic_name=clinic.ClinicName)
        for clinic in clinics
    ]

    return clinic_details


@router.post("/create-patient/")
async def create_patient(patient: PatientCreationDetails, request: Request, db_conn: Session = Depends(get_db),):
    """
    Create a new patient record and link it to the requesting merchant.

    Sanitises name inputs, checks for duplicate patients by name + DOB + gender,
    then creates the patient and grants the merchant access.

    :param patient: Patient creation details (names, DOB, gender, weight, height).
    :param request: The HTTP request (for current-merchant extraction).
    :param db_conn: Database session.
    :return: A dict with a success message and the new ``patient_id``.
    :raises HTTPException 422: If any input field fails validation.
    :raises HTTPException 409: If a matching patient already exists.
    """
    # Check if the requesting user is a merchant.
    merchant = get_current_merchant(request, db_conn)

    # Validate all user input
    if (not is_name_valid(patient.given_names) or
        not is_name_valid(patient.family_name) or
        not is_gender_valid(patient.gender) or
        not is_age_valid(patient.date_of_birth) or
        not is_weight_valid(patient.weight) or
            not is_height_valid(patient.height)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    # Sanitize name input and remove whitespace
    sanitizer = Sanitizer()
    sanitized_given_names = sanitizer.sanitize(patient.given_names).strip()
    sanitized_family_name = sanitizer.sanitize(patient.family_name).strip()

    # Check if the patient already exists
    existing_patient = db_conn.query(Patient).filter(
        func.lower(Patient.GivenNames) == sanitized_given_names.lower(),
        func.lower(Patient.FamilyName) == sanitized_family_name.lower(),
        Patient.DateOfBirth == patient.date_of_birth,
        Patient.Gender == gender_map[patient.gender]
    ).first()

    if existing_patient:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Patient already exists."
        )

    # Create new patient
    new_patient = Patient(user_id=None,
                          given_names=sanitized_given_names,
                          family_name=sanitized_family_name,
                          gender=gender_map[patient.gender],
                          date_of_birth=patient.date_of_birth,
                          weight=patient.weight,
                          height=patient.height)
    db_conn.add(new_patient)
    db_conn.commit()

    db_conn.refresh(new_patient)
    # Provide merchant access to view patient information
    patient_id = new_patient.PatientID
    merchant_id = merchant.UserID

    merchant_access = UserPatientAccess(
        user_id=merchant_id, patient_id=patient_id)
    db_conn.add(merchant_access)
    db_conn.commit()

    return {
        "message": "Patient successfully created.",
        "patient_id": patient_id
    }


@router.delete("/remove-patient/{patient_id}")
async def remove_patient(patient_id: str, request: Request, db_conn: Session = Depends(get_db),):
    """Deletes relationship between patient and merchant"""
    # Check if the requesting user is a merchant.
    merchant = get_current_merchant(request, db_conn)
    merchant_id = merchant.UserID

    # Check if the merchant has access to the patients record
    merchant_access = db_conn.query(UserPatientAccess).filter(
        UserPatientAccess.UserID == merchant_id,
        UserPatientAccess.PatientID == patient_id
    ).first()

    if not merchant_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

    # Remove relationship between the merchant and patient
    db_conn.delete(merchant_access)
    db_conn.commit()

    return {'message': 'Patient successfully removed.'}


@router.get("/merchant/associated-patients")
async def associated_patients(request: Request, given_names: str = None, family_name: str = None, skip: int = 0, limit: int = 25, db_conn: Session = Depends(get_db)):
    """Deletes relationship between patient and merchant"""
    # Check if the requesting user is a merchant.
    current_merchant = get_current_merchant(request, db_conn)
    merchant_id = current_merchant.UserID

    # Retrieve patient information
    query = (db_conn.query(Patient.PatientID, Patient.GivenNames, Patient.FamilyName, Patient.Gender, Patient.DateOfBirth)
             .join(UserPatientAccess, UserPatientAccess.PatientID == Patient.PatientID)
             .filter(UserPatientAccess.UserID == merchant_id)
             )
    # Filter by search parameters
    if (given_names):
        query = query.filter(Patient.GivenNames.ilike(f"%{given_names}%"))
    if (family_name):
        query = query.filter(Patient.FamilyName.ilike(f"%{family_name}%"))
    # Paginate query
    total_patients = query.count()
    patient_info = query.order_by(
        Patient.CreatedAt.desc()).offset(skip).limit(limit).all()

    return {
        "patients": [
           {
               "patientId": patient.PatientID,
               "givenNames": patient.GivenNames,
               "familyName": patient.FamilyName,
               "gender": "Male" if patient.Gender == 1 else "Female" if patient.Gender == 0 else "",
               "dateOfBirth": patient.DateOfBirth.strftime("%d/%m/%Y"),
           }
            for patient in patient_info
        ],
        "totalPatients": total_patients

    }


def get_current_merchant(request: Request, db_conn):
    """
    Verify the requesting user is a merchant and return their ``UserAccount``.

    :param request: The HTTP request (for cookie-based user extraction).
    :param db_conn: Database session.
    :return: The ``UserAccount`` object of the merchant.
    :raises HTTPException 404: If the user is not found.
    :raises HTTPException 403: If the user's role is not ``merchant``.
    """

    # Check if the requesting user is a merchant.
    current_user = get_current_user(request, db_conn)
    current_user_email = current_user.get('email')
    merchant = db_conn.query(UserAccount).filter_by(
        Email=current_user_email).first()
    if not merchant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    current_user_role = current_user.get('role')
    if not current_user_role or current_user_role.lower() != "merchant":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")
    return merchant


def get_merchant_patients(merchantID: int, db_conn):
    '''Get all patients that belong to the merchant user'''
    return (db_conn.query(Patient)
            .join(UserPatientAccess, UserPatientAccess.PatientID == Patient.PatientID)
            .filter(UserPatientAccess.UserID == merchantID)
            .order_by(Patient.CreatedAt.desc())
            .all()
            )


@router.get("/dashboard", response_model=Dashboard)
async def get_dashboard(request: Request, db_conn: Session = Depends(get_db)):
    """
    Return the authenticated user's dashboard with latest risks, trends, and recommendations.

    Fetches the last 5 predictions and calculates risk deltas, days since last
    report, and the most recent AI-generated recommendations.

    :param request: The HTTP request (for current-user extraction).
    :param db_conn: Database session.
    :return: A ``Dashboard`` object containing ``days``, ``risks``, ``diff``,
             and ``recommendations``.
    :raises HTTPException 404: If the patient record is not found.
    """
    user = get_current_user(request, db_conn)
    patient = get_patient_by_email(user["email"], db_conn)

    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found.")

    patient_id = patient.PatientID

    # Fetch patient health data.
    health_rows = (db_conn.query(HealthData).filter(HealthData.PatientID == patient_id)
                   .order_by(HealthData.CreatedAt.desc()).limit(5).all())

    if not health_rows:
        return Dashboard(
            days=0,
            risks={},
            diff={},
            recommendations={},
        )

    # Calculate days since previous report submission.
    days_since_prev = (datetime.now() - health_rows[0].CreatedAt).days

    predictions = (db_conn.query(Prediction).join(HealthData, Prediction.HealthDataID == HealthData.HealthDataID)
                   .filter(HealthData.PatientID == patient_id)
                   .order_by(Prediction.CreatedAt.desc()).limit(5).all())

    # Latest disease prediction.
    stroke_risk = float(predictions[0].StrokeChance) if predictions else 0.0
    diabetes_risk = float(
        predictions[0].DiabetesChance) if predictions else 0.0
    cvd_risk = float(predictions[0].CVDChance) if predictions else 0.0

    # Risk over time trends.
    risk_dates = [p.CreatedAt.strftime("%d/%m/%Y") for p in predictions]

    latest_risk_info = {
        "dates": risk_dates,
        "stroke": [float(p.StrokeChance or 0) for p in predictions],
        "diabetes": [float(p.DiabetesChance or 0) for p in predictions],
        "cvd": [float(p.CVDChance or 0) for p in predictions],
    }

    # Calculate the difference in disease percentage.
    disease_diff = {
        "stroke": 0.0,
        "cvd": 0.0,
        "diabetes": 0.0,
    }

    if predictions and len(predictions) > 1:
        current = predictions[0]
        prev = predictions[1]

        disease_diff["stroke"] = float(
            current.StrokeChance) - float(prev.StrokeChance)
        disease_diff["cvd"] = float(
            current.CVDChance) - float(prev.CVDChance)
        disease_diff["diabetes"] = float(
            current.DiabetesChance) - float(prev.DiabetesChance)

    # Get the latest patient recommendations.
    recommendation = (db_conn.query(Recommendation).join(HealthData, Recommendation.HealthDataID == HealthData.HealthDataID)
                      .filter(HealthData.PatientID == patient_id).order_by(Recommendation.CreatedAt.desc())
                      .first())

    latest_recommendations = {
        "exercise": recommendation.ExerciseRecommendation if recommendation else "No latest recommendation",
        "diet": recommendation.DietRecommendation if recommendation else "No latest recommendation",
        "lifestyle": recommendation.LifestyleRecommendation if recommendation else "No latest recommendation",
        "avoid": recommendation.DietToAvoidRecommendation if recommendation else "No latest recommendation",
    }

    return Dashboard(
        days=days_since_prev,
        risks=latest_risk_info,
        diff=disease_diff,
        recommendations=latest_recommendations,
    )


@router.get("/merchant-dashboard", response_model=MerchantDashboard)
async def get_merchant_dashboard(request: Request, db_conn: Session = Depends(get_db)):
    """
    Return the merchant dashboard with patient/report stats and risk distributions.

    Aggregates data across all patients linked to the merchant: total and
    inactive patient counts, report volumes, per-disease risk distribution
    (high / moderate / low), and recent report activity.

    :param request: The HTTP request (for current-merchant extraction).
    :param db_conn: Database session.
    :return: A ``MerchantDashboard`` object with aggregated analytics.
    """

    merchant = get_current_merchant(request, db_conn)
    merchant_id = merchant.UserID

    # get all merchant patients
    patients = get_merchant_patients(merchant_id, db_conn)
    patient_ids = [p.PatientID for p in patients]
    total_patients = len(patient_ids)

    if total_patients == 0:
        return MerchantDashboard(
            total_patients=0,
            total_reports=0,
            reports_last_30_days=0,
            inactive_patients=0,
            risk_distribution={},
            report_activity=[]
        )

    health_data = (
        db_conn.query(HealthData)
        .filter(HealthData.PatientID.in_(patient_ids))
        .all()
    )

    total_reports = len(health_data)

    # Report in last 30 days
    last_30_days = datetime.now() - timedelta(days=30)
    reports_last_30 = 0
    reports_by_date = {}

    for row in health_data:
        if row.CreatedAt >= last_30_days:
            reports_last_30 += 1

    # Inactive patients
    inactive_patients = 0

    for patient in patients:
        latest = (db_conn.query(HealthData).filter(HealthData.PatientID == patient.PatientID)
                  .order_by(HealthData.CreatedAt.desc()).first())

        if not latest or latest.CreatedAt < last_30_days:
            inactive_patients += 1

    # Total Patient Risks
    stroke_high = stroke_mod = stroke_low = 0
    cvd_high = cvd_mod = cvd_low = 0
    diabetes_high = diabetes_mod = diabetes_low = 0

    for patient in patients:
        prediction = (db_conn.query(Prediction).join(HealthData, Prediction.HealthDataID == HealthData.HealthDataID)
                      .filter(HealthData.PatientID == patient.PatientID).order_by(Prediction.CreatedAt.desc())
                      .first())

        if not prediction:
            continue

        stroke = float(prediction.StrokeChance or 0)
        cvd = float(prediction.CVDChance or 0)
        diabetes = float(prediction.DiabetesChance or 0)

        if stroke >= 50:
            stroke_high += 1
        elif stroke >= 30:
            stroke_mod += 1
        else:
            stroke_low += 1

        if cvd >= 50:
            cvd_high += 1
        elif cvd >= 30:
            cvd_mod += 1
        else:
            cvd_low += 1

        if diabetes >= 50:
            diabetes_high += 1
        elif diabetes >= 30:
            diabetes_mod += 1
        else:
            diabetes_low += 1

    # Report activity
    recent_activity = []

    reports = (db_conn.query(HealthData).filter(HealthData.PatientID.in_(patient_ids))
               .order_by(HealthData.CreatedAt.desc()).limit(20).all())

    for report in reports:
        patient = db_conn.query(Patient).filter_by(
            PatientID=report.PatientID).first()
        recent_activity.append({
            "message": f"{patient.GivenNames} {patient.FamilyName} submitted report",
            "createdAt": report.CreatedAt.isoformat()
        })

    return MerchantDashboard(
        total_patients=total_patients,
        total_reports=total_reports,
        reports_last_30_days=reports_last_30,
        inactive_patients=inactive_patients,
        risk_distribution={
            "stroke": {"high": stroke_high, "moderate": stroke_mod, "low": stroke_low},
            "cvd": {"high": cvd_high, "moderate": cvd_mod, "low": cvd_low},
            "diabetes": {"high": diabetes_high, "moderate": diabetes_mod, "low": diabetes_low},
        },
        report_activity=recent_activity
    )


@router.get("/patient-data")
async def get_patient_data(request: Request, db_conn: Session = Depends(get_db)):
    """Return the authenticated user's patient data for report form inputs."""

    # Get current user details.
    user = get_current_user(request, db_conn)
    patient = get_patient_by_email(user["email"], db_conn)

    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found.")

    result = {
        "weight": float(patient.Weight) if patient.Weight else None,
        "height": float(patient.Height) if patient.Height else None,
        "gender": get_gender(patient.Gender),
        "age": get_age(patient.DateOfBirth),
        "maritalStatus": patient.get_marital_status(),
        "workingStatus": patient.get_working_status(),
        "race": patient.get_race()
    }

    return result


@router.get("/merchant/patient-data/{patient_id}")
async def get_merchant_patient_data(patient_id: int, request: Request, db_conn: Session = Depends(get_db)):
    """Return a patient's data for merchant report form inputs."""

    # Check if the requesting user is a merchant.
    current_user = get_current_user(request, db_conn)
    current_user_email = current_user.get('email')
    merchant = db_conn.query(UserAccount).filter_by(
        Email=current_user_email).first()
    if not merchant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    current_user_role = current_user.get('role')
    if not current_user_role or current_user_role.lower() != 'merchant':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

    # Get the patient by ID.
    patient = (db_conn.query(Patient).filter(
        Patient.PatientID == patient_id).first())

    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found.")

    result = {
        "weight": float(patient.Weight) if patient.Weight else None,
        "height": float(patient.Height) if patient.Height else None,
        "gender": get_gender(patient.Gender),
        "age": get_age(patient.DateOfBirth),
        "maritalStatus": patient.get_marital_status(),
        "workingStatus": patient.get_working_status(),
        "race": patient.get_race()
    }

    return result


@router.get("/patient-details/{patient_id}", response_model=PatientDetails)
async def get_dashboard(patient_id: str, request: Request, db_conn: Session = Depends(get_db)):
    """Returns a patient's details"""
    # Check if current user is a merchant
    merchant = get_current_merchant(request, db_conn)

    # Check if the merchant has access to the patients record
    merchant_id = merchant.UserID
    merchant_access = db_conn.query(UserPatientAccess).filter(
        UserPatientAccess.UserID == merchant_id,
        UserPatientAccess.PatientID == patient_id
    ).first()

    if not merchant_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

    query = (db_conn.query(Patient.GivenNames, Patient.FamilyName,
                           Patient.Gender, Patient.DateOfBirth, Patient.Height, Patient.Weight)
             .filter(Patient.PatientID == patient_id)
             .first())

    patient_info = {
        "givenNames": query.GivenNames,
        "familyName": query.FamilyName,
        "gender": query.Gender,
        "dateOfBirth": query.DateOfBirth.strftime("%d/%m/%Y"),
        "height": query.Height,
        "weight": query.Weight,
        "age": calculateAge(query.DateOfBirth)
    }

    # Fetch patient health data.
    health_rows = (db_conn.query(HealthData).filter(HealthData.PatientID == patient_id)
                   .order_by(HealthData.CreatedAt.desc()).limit(5).all())

    if not health_rows:
        return PatientDetails(
            patient_info=patient_info,
            days=0,
            risks={},
            diff={},
            recommendations={}
        )

    # Calculate days since previous report submission.
    days_since_prev = (datetime.now() - health_rows[0].CreatedAt).days

    predictions = (db_conn.query(Prediction).join(HealthData, Prediction.HealthDataID == HealthData.HealthDataID)
                   .filter(HealthData.PatientID == patient_id)
                   .order_by(Prediction.CreatedAt.desc()).limit(5).all())

    # Risk over time trends.
    risk_dates = [p.CreatedAt.strftime("%d/%m/%Y") for p in predictions]

    latest_risk_info = {
        "dates": risk_dates,
        "stroke": [float(p.StrokeChance or 0) for p in predictions],
        "diabetes": [float(p.DiabetesChance or 0) for p in predictions],
        "cvd": [float(p.CVDChance or 0) for p in predictions],
    }

    # Calculate the difference in disease percentage.
    disease_diff = {
        "stroke": 0.0,
        "cvd": 0.0,
        "diabetes": 0.0,
    }

    if predictions and len(predictions) > 1:
        current = predictions[0]
        prev = predictions[1]

        disease_diff["stroke"] = float(
            current.StrokeChance) - float(prev.StrokeChance)
        disease_diff["cvd"] = float(current.CVDChance) - float(prev.CVDChance)
        disease_diff["diabetes"] = float(
            current.DiabetesChance) - float(prev.DiabetesChance)

    # Get the latest patient recommendations.
    recommendation = (db_conn.query(Recommendation).join(HealthData, Recommendation.HealthDataID == HealthData.HealthDataID)
                      .filter(HealthData.PatientID == patient_id).order_by(Recommendation.CreatedAt.desc())
                      .first())

    latest_recommendations = {
        "exercise": recommendation.ExerciseRecommendation if recommendation else "No latest recommendation",
        "diet": recommendation.DietRecommendation if recommendation else "No latest recommendation",
        "lifestyle": recommendation.LifestyleRecommendation if recommendation else "No latest recommendation",
        "avoid": recommendation.DietToAvoidRecommendation if recommendation else "No latest recommendation",
    }

    return PatientDetails(
        patient_info=patient_info,
        days=days_since_prev,
        risks=latest_risk_info,
        diff=disease_diff,
        recommendations=latest_recommendations
    )


@router.post('/patient-request')
def patient_request(patient_request: PatientRequest, request: Request, db_conn: Session = Depends(get_db)):
    """
    Generate a time-limited access token and email a patient access request.

    The merchant can request access to a patient's records via email. A
    7-day token is created and emailed to the patient for approval.
    Only one active token is allowed per merchant-patient pair.

    :param patient_request: Object containing the patient's email address.
    :param request: The HTTP request (for current-merchant extraction).
    :param db_conn: Database session.
    :return: A dict with a success message.
    :raises HTTPException 422: If the email is invalid.
    :raises HTTPException 404: If no patient is found for the email.
    :raises HTTPException 409: If the merchant already has access to the patient.
    """

    # Check the current user is a merchant
    merchant = get_current_merchant(request, db_conn)

    sanitised_email = re.sub(r'[()<>[\]:,;\\]', '',
                             patient_request.email)
    if not is_email_valid(sanitised_email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    # Check if the provided email is a patient
    patient = get_patient_by_email(sanitised_email, db_conn)

    if patient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found.")

    # Check if the merchant currently has access to the patient account
    merchant_access = db_conn.query(UserPatientAccess).filter(
        UserPatientAccess.UserID == merchant.UserID,
        UserPatientAccess.PatientID == patient.PatientID
    ).first()

    if merchant_access:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Access already exists"
        )

    # Only allow one token to exist per patient & merchant pair.
    existing_token = db_conn.query(
        PatientRequestToken).filter_by(MerchantID=merchant.UserID, PatientID=patient.PatientID).first()
    if existing_token:
        db_conn.delete(existing_token)
    # Create patient request token
    token = token_urlsafe(VALIDATION_TOKEN_LENGTH)
    expires_at = datetime.now() + timedelta(days=7)
    patient_access_token = PatientRequestToken(
        merchant.UserID,
        patient.PatientID,
        token,
        expires_at
    )

    db_conn.add(patient_access_token)
    db_conn.commit()

    clinic = db_conn.query(Clinic.ClinicName).filter(
        Clinic.ClinicID == merchant.ClinicID
    ).scalar()

    if clinic is None:
        clinic = ""

    send_patient_request_email(
        sanitised_email, patient, clinic, request, token)
    return {"message": "Patient access request sent successfully"}


@router.post('/patient-accept-request')
def patient_accept_request(patient_accept_details: PatientAcceptDetails, request: Request, db_conn: Session = Depends(get_db)):
    """
    Verify a patient-access token and grant the merchant access to the patient's records.

    The authenticated standard user must match the patient the request was
    created for. On success, the token is consumed and a ``UserPatientAccess``
    row is created.

    :param patient_accept_details: Object containing the signed access token.
    :param request: The HTTP request (for current-user extraction).
    :param db_conn: Database session.
    :return: A dict with a success message.
    :raises HTTPException 403: If the user is not a standard user or doesn't match the patient.
    :raises HTTPException 404: If the token is invalid, expired, or the patient is not found.
    """

    # Get current user's details
    current_user = get_current_user(request, db_conn)
    current_user_role = current_user.get("role")
    if not current_user_role or current_user_role.lower() != "standard_user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

    user = get_user(current_user["email"], db_conn)

    # Retrieve token
    token_entry = db_conn.query(
        PatientRequestToken).filter_by(Token=patient_accept_details.token).first()

    if not token_entry or datetime.now(UTC) > token_entry.ExpiresAt.astimezone(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired request"
        )

    # Check the user is a patient
    patient = db_conn.query(Patient).filter(
        Patient.UserID == user.UserID).first()
    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid or expired request")

    # Check the user who validated their credentials is the patient the request was created for
    if patient.PatientID != token_entry.PatientID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.",
        )

    # Create relationship between patient and merchant
    merchant_access = UserPatientAccess(
        user_id=token_entry.MerchantID, patient_id=token_entry.PatientID)
    db_conn.delete(token_entry)
    db_conn.add(merchant_access)
    db_conn.commit()

    return {"message": "Merchant access successfully granted"}


def send_patient_request_email(
    email: str,
    patient: Patient,
    clinic: str,
    request: Request,
    token: str
):
    """
    Send a branded email to a patient requesting permission
    for a merchant to access their health records.

    All dynamic content is sanitised before embedding it
    in the HTML email body.

    :param email: The recipient patient's email address.
    :param patient: The patient's profile.
    :param clinic: The requesting clinic's name.
    :param request: The HTTP request.
    :param token: The unsigned access-request token.
    """
    sanitizer = Sanitizer()

    sanitized_token = sanitizer.sanitize(token)
    given_names = sanitizer.sanitize(patient.GivenNames)
    family_name = sanitizer.sanitize(patient.FamilyName)
    clinic_name = sanitizer.sanitize(clinic)

    frontend_url = os.getenv(
        "FRONTEND_URL",
        "https://smart-health-predictive.vercel.app"
    )

    access_request_url = (
        f"{frontend_url}/accept-access-request/{sanitized_token}"
    )

    logo_path = (
        Path(__file__).resolve().parent.parent
        / "static"
        / "images"
        / "wellai-logo.png"
    )

    subject = "Patient Access Request - WellAI Smart Health Predictive"

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
                        Patient Access Request
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
                        <strong>{clinic_name}</strong> has requested
                        permission to access your health records through
                        WellAI Smart Health Predictive.
                    </p>

                    <p style="
                        font-size: 16px;
                        line-height: 1.6;
                        margin: 0 0 10px 0;
                    ">
                        If you approve this request, the clinic will be able to:
                    </p>

                    <!-- Access permissions -->
                    <div style="
                        background-color: #f8f4fa;
                        border-left: 4px solid #6F2C91;
                        padding: 15px 18px;
                        margin: 20px 0;
                    ">
                        <ul style="
                            margin: 0;
                            padding-left: 20px;
                            color: #444444;
                            font-size: 14px;
                            line-height: 1.7;
                        ">
                            <li>View your health report history</li>
                            <li>Generate new health reports based on your data</li>
                            <li>View your health data</li>
                        </ul>
                    </div>

                    <!-- Approval button -->
                    <div style="
                        text-align: center;
                        margin: 30px 0;
                    ">
                        <a
                            href="{access_request_url}"
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
                            Review Access Request
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
                            This access request link will expire in
                            <strong>7 days</strong>.
                        </p>
                    </div>

                    <p style="
                        font-size: 14px;
                        line-height: 1.6;
                        color: #666666;
                        margin-top: 25px;
                    ">
                        If you did not expect this request, you can safely
                        ignore this email. Your health records will not be
                        shared unless you approve the request.
                    </p>

                    <p style="
                        font-size: 14px;
                        line-height: 1.6;
                        color: #666666;
                    ">
                        For your security, please do not forward this email
                        or share your access-request link with anyone.
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
        recipient=email,
        subject=subject,
        content=content,
        content_type="html",
        inline_image_path=str(logo_path),
        inline_image_cid="wellai-logo"
    )

def is_name_valid(name: str):
    '''Verifies a name is valid.'''
    return name is not None or len(name) <= NAME_MAX_LENGTH


def is_age_valid(date_of_birth: date):
    '''Verifies age is valid and the user is at least 18'''

    return calculateAge(date_of_birth) >= MIN_AGE


def calculateAge(date_of_birth: date):
    '''Calculate age based on a date'''
    # Check current date
    today = date.today()
    year_diff = today.year - date_of_birth.year

    # checks if the persons birthday has happened this year
    birthday_not_passed = ((today.month, today.day) < (
        date_of_birth.month, date_of_birth.day))

    age = year_diff - birthday_not_passed
    return age


def is_gender_valid(gender: str):
    '''Verifies gender is valid'''
    return gender in gender_map


def is_weight_valid(weight: float):
    '''Verifies weight is valid'''
    return 0.0 <= weight <= 200.0


def is_height_valid(height: float):
    '''Verifies height is valid'''
    return 0.0 <= height <= 300.0


def get_age(dob):
    """Calculates an age given a date of birth."""
    if not dob:
        return None

    today = datetime.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def get_gender(gender):
    """Returns a string representation of a users gender."""
    return "Male" if gender == 1 else "Female"