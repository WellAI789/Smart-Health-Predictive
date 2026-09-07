from datetime import datetime, date, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi_camelcase import CamelModel
from sqlalchemy.orm import Session
from sqlalchemy import or_, asc, desc
from typing import List, Optional
from pydantic import BaseModel

from sqlalchemy import func, extract, desc

from ..utils.database import get_db
from ..utils.audit_log import write_audit_log
from ..models.dbmodels import (
    UserAccount,
    UserAccountRole,
    AccountRole,
    UserAccountValidationToken,
    HealthData,
    Prediction,
    Recommendation,
    AuditLog,
    LogEventType,
    Patient,
    Clinic,
    UserPatientAccess
)
from ..routers.authentication import get_current_user, get_patient_by_email

router = APIRouter()


class AdminReportAnalytics(CamelModel):
    total_reports: int


class ActiveAccountAnalytics(CamelModel):
    past_month: int
    past_week: int


class ActiveMerchantAnalytics(CamelModel):
    past_month: int
    past_week: int


class RecentReportsGeneratedAnalytics(CamelModel):
    past_month: int
    past_week: int


class PendingMerchantAnalytics(CamelModel):
    amount: int


class UnvalidatedAccountsAnalytic(CamelModel):
    amount: int


class LoginActivity(CamelModel):
    amount_by_day: dict


class AdminUserAnalytics(CamelModel):
    total_accounts: int
    total_standard: int
    total_patients: int
    total_merchants: int


@router.get("/roles")
async def get_roles(db_conn: Session = Depends(get_db)):
    """Return all roles"""

    roles = db_conn.query(AccountRole).all()

    result = []
    for role in roles:
        result.append({
            "id": role.RoleID if role else None,
            "name": role.RoleName if role else None,
        })

    return result


@router.get("/users")
async def get_users(
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
    clinic_id: Optional[int] = None,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = "desc",
    db_conn: Session = Depends(get_db)
):
    """
    Return a paginated, filterable, sortable list of validated user accounts.

    Supports searching by email, patient name, or clinic name; filtering by
    clinic; and sorting by email, creation date, or validation status.

    :param skip: Number of records to skip (offset).
    :param limit: Maximum number of records to return.
    :param search: Optional keyword to search across email, name, and clinic.
    :param clinic_id: Optional clinic ID to filter users.
    :param sort_by: Column name to sort by (email, createdAt, validated).
    :param sort_order: Sort direction (asc or desc).
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A dict with ``users`` (list) and ``total`` (count).
    :raises HTTPException 400: If ``skip`` is negative or ``limit`` is not positive.
    """

    if skip < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="skip must be greater than or equal to 0")
    if limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="limit must be greater than 0")

    # Mapping from frontend column field names to sortable DB columns
    SORT_FIELD_MAP = {
        "email": UserAccount.Email,
        "createdAt": UserAccount.CreatedAt,
        "validated": UserAccount.IsValidated,
        "fullName": None,
        "role": None,
    }

    # Query users and roles, then apply pagination.
    query = db_conn.query(UserAccount, AccountRole, Patient, Clinic) \
        .filter(UserAccount.IsValidated == True) \
        .outerjoin(UserAccountRole, UserAccount.UserID == UserAccountRole.UserID) \
        .outerjoin(AccountRole, UserAccountRole.RoleID == AccountRole.RoleID) \
        .outerjoin(Patient, Patient.UserID == UserAccount.UserID) \
        .outerjoin(Clinic, Clinic.ClinicID == UserAccount.ClinicID)

    if search:
        keyword = f"%{search.strip()}%"
        if keyword != "%%":
            query = query.filter(
                or_(
                    UserAccount.Email.ilike(keyword),
                    Patient.GivenNames.ilike(keyword),
                    Patient.FamilyName.ilike(keyword),
                    Clinic.ClinicName.ilike(keyword),
                )
            )
    
    if clinic_id:
        merchants = db_conn.query(UserAccount.UserID).filter(UserAccount.ClinicID == clinic_id)

        patients = (db_conn.query(Patient.UserID)
                .join(UserPatientAccess, UserPatientAccess.PatientID == Patient.PatientID)
                .join(UserAccount, UserAccount.UserID == UserPatientAccess.UserID)
                .filter(UserAccount.ClinicID == clinic_id))

        query = query.filter(or_(UserAccount.UserID.in_(merchants), UserAccount.UserID.in_(patients)))

    total_count = query.count()

    # Determine sort column fall back to CreatedAt desc when unsortable or unknown
    sort_col = SORT_FIELD_MAP.get(sort_by) if sort_by else None
    if sort_col is not None:
        order_fn = asc if (sort_order or "desc").lower() == "asc" else desc
        order_clause = order_fn(sort_col)
    else:
        order_clause = UserAccount.CreatedAt.desc()

    users = query.order_by(order_clause).offset(skip).limit(limit).all()

    result = []
    for user, role, patient, clinic in users:
        full_name = ""

        # Retrieve the patients full name for a standard  user
        if role and role.RoleName == "standard_user":
            if patient:
                full_name = f'{patient.GivenNames} {patient.FamilyName}'

        # Retrieve Clinic name for a merchant user
        if role and role.RoleName == "merchant":
            if clinic:
                full_name = clinic.ClinicName

        result.append({
            "fullName": full_name,
            "email": user.Email,
            "phoneNumber": user.PhoneNumber,
            "createdAt": user.CreatedAt,
            "validated": user.IsValidated,
            "role": {
                "id": role.RoleID if role else None,
                "name": role.RoleName if role else None
            }
        })

    return {
        "users": result,
        "total": total_count
    }


@router.patch("/users/{user_email}/roles/{role_id}")
async def update_user_role(user_email: str, role_id: int, request: Request,
                           db_conn: Session = Depends(get_db)):
    """
    Update a user's role to the specified role ID.

    Verifies the requesting user is an administrator, prevents self-role
    changes, and creates or updates the ``UserAccountRole`` mapping.
    An audit log is written on both success and failure.

    :param user_email: The email of the target user whose role will change.
    :param role_id: The ``RoleID`` to assign to the user.
    :param request: The HTTP request (for current-user extraction and audit logging).
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A dict with a success message and the assigned role info.
    :raises HTTPException 401: If the requesting user cannot be identified.
    :raises HTTPException 403: If the requesting user is not an admin.
    :raises HTTPException 404: If the user or role is not found.
    :raises HTTPException 400: If an admin attempts to change their own role.
    """
    # Authenticate the requesting user.
    current_user_data = get_current_user(request, db_conn)
    requesting_user_email = current_user_data.get('email')

    # Verify the requesting user is an administrator.
    admin_user = db_conn.query(UserAccount).filter(
        UserAccount.Email == requesting_user_email).first()
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not identify the requesting user.")

    admin_role = db_conn.query(AccountRole).join(
        UserAccountRole, AccountRole.RoleID == UserAccountRole.RoleID
    ).filter(UserAccountRole.UserID == admin_user.UserID).first()

    if not admin_role or admin_role.RoleName.lower() != 'admin':
        write_audit_log(db_conn,
                        eventType=LogEventType.ROLE_CHANGED,
                        success=False,
                        userEmail=requesting_user_email,
                        device=request.headers.get("user-agent"),
                        ipAddress=request.client.host,
                        description=f"Unauthorized role change attempt for account: {user_email}.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to change user roles.")

    # Check if both the user and role exist.
    user = db_conn.query(UserAccount).filter(
        UserAccount.Email == user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Prevent admin from changing their own role.
    if admin_user.UserID == user.UserID:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Administrators cannot change their own role.")

    role = db_conn.query(AccountRole).filter(
        AccountRole.RoleID == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    # Check if role mapping exists for the user.
    current_user_role = db_conn.query(UserAccountRole).filter(
        UserAccountRole.UserID == user.UserID).first()

    # Update the user's role otherwise make new mapping.
    if current_user_role:
        current_user_role.RoleID = role_id
    else:
        db_conn.add(UserAccountRole(UserID=user.UserID, RoleID=role_id))

    db_conn.commit()

    write_audit_log(db_conn,
                    eventType=LogEventType.ROLE_CHANGED,
                    success=True,
                    userEmail=requesting_user_email,
                    device=request.headers.get("user-agent"),
                    ipAddress=request.client.host,
                    description=f"Role changed for {user_email} to {role.RoleName}.")

    return {"message": f"Update successful.",
            "role": {
                "id": role.RoleID,
                "name": role.RoleName,
            }}


def _delete_user_data(user_email: str, db_conn: Session):
    """
    Delete a user and all their associated data, returning a report of the deletion.

    Removes patient access links, recommendations, predictions, health data,
    validation tokens, and role mappings in the correct order to avoid
    foreign-key violations. Rolls back on failure.

    :param user_email: The email of the account to delete.
    :param db_conn: Database session.
    :return: A dict with counts of deleted records per table.
    :raises HTTPException 404: If the user is not found.
    :raises HTTPException 500: If the deletion fails.
    """
    deletion_report = {}

    try:
        # Find the user to ensure they exist before proceeding
        user_to_delete = db_conn.query(UserAccount).filter(
            UserAccount.Email == user_email).first()
        if not user_to_delete:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        # Collect all HealthDataIDs for this user
        patient_record = get_patient_by_email(user_email, db_conn)

        # Delete Merchant access to patient record
        if patient_record:
            db_conn.query(UserPatientAccess).filter(UserPatientAccess.PatientID ==
                                                    patient_record.PatientID).delete(synchronize_session=False)
        else:
            db_conn.query(UserPatientAccess).filter(
                UserPatientAccess.UserID == user_to_delete.UserID).delete(synchronize_session=False)

        if patient_record:
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
            UserAccountValidationToken.UserID == user_to_delete.UserID).delete(synchronize_session=False)
        deletion_report['validation_tokens_deleted'] = tokens_deleted

        roles_deleted = db_conn.query(UserAccountRole).filter(
            UserAccountRole.UserID == user_to_delete.UserID).delete(synchronize_session=False)
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


@router.delete("/users/{user_email}")
async def delete_user_by_admin(user_email: str, request: Request, db_conn: Session = Depends(get_db)):
    """
    Delete a user account and all associated data (admin only).

    Verifies the requesting user is an administrator, prevents self-deletion,
    then cascades to remove health data, predictions, recommendations, and
    role mappings. An audit log is written on both success and failure.

    :param user_email: The email of the user account to delete.
    :param request: The HTTP request (for current-user extraction and audit logging).
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A dict with a success message and a ``deletion_report``.
    :raises HTTPException 401: If the requesting user cannot be identified.
    :raises HTTPException 403: If the requesting user is not an admin.
    :raises HTTPException 404: If the target user is not found.
    :raises HTTPException 400: If an admin attempts to delete their own account.
    """
    # Get the current user making the request
    current_user_data = get_current_user(request, db_conn)
    requesting_user_email = current_user_data.get('email')

    # Verify the requesting user is an administrator
    admin_user = db_conn.query(UserAccount).filter(
        UserAccount.Email == requesting_user_email).first()
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not identify the requesting user.")

    user_role = db_conn.query(AccountRole).join(UserAccountRole, AccountRole.RoleID ==
                                                UserAccountRole.RoleID).filter(UserAccountRole.UserID == admin_user.UserID).first()

    if not user_role or user_role.RoleName.lower() != 'admin':
        write_audit_log(db_conn,
                        eventType=LogEventType.ACCOUNT_DELETED,
                        success=False,
                        userEmail=requesting_user_email,
                        device=request.headers.get("user-agent"),
                        ipAddress=request.client.host,
                        description=f"Unauthorized delete attempt for account: {user_email}.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to delete users.")

    # Find the user to delete to get their details before deletion
    user_to_delete = db_conn.query(UserAccount).filter(
        UserAccount.Email == user_email).first()
    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User to delete not found.")

    # Prevent admin from deleting themselves
    if admin_user.UserID == user_to_delete.UserID:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Administrators cannot delete their own accounts.")

    # Perform the deletion and get the report
    deletion_report = _delete_user_data(user_email, db_conn)

    write_audit_log(db_conn,
                    eventType=LogEventType.ACCOUNT_DELETED,
                    success=True,
                    userEmail=requesting_user_email,
                    device=request.headers.get("user-agent"),
                    ipAddress=request.client.host,
                    description=f"Admin deleted account: {user_email}.")

    return {
        "message": f"User with Email {user_email} and all related data deleted successfully",
        "deletion_report": deletion_report
    }


@router.get("/users/merchants/")
async def get_invalid_merchant_accounts(db_conn: Session = Depends(get_db)):
    """Return all merchant accounts that are not validated"""
    # Query all invalid merchant accounts.
    invalid_merchant_accounts = db_conn.query(UserAccount) \
        .outerjoin(UserAccountRole, UserAccount.UserID == UserAccountRole.UserID) \
        .outerjoin(AccountRole, UserAccountRole.RoleID == AccountRole.RoleID) \
        .filter(AccountRole.RoleName == "merchant") \
        .filter(UserAccount.IsValidated == False) \
        .all()

    result = []
    for merchant in invalid_merchant_accounts:

        full_name = (db_conn.query(Clinic).filter(
            Clinic.ClinicID == merchant.ClinicID).first()).ClinicName

        result.append({
            "fullName": full_name,
            "email": merchant.Email,
            "phoneNumber": merchant.PhoneNumber,
            "createdAt": merchant.CreatedAt,
        })

    return result


@router.patch("/users/merchants/{merchant_email}")
async def validate_merchant(merchant_email: str, request: Request, db_conn: Session = Depends(get_db)):
    """
    Validate a pending merchant account so they can access the platform.

    Verifies the requesting user is an administrator, then sets the
    merchant's ``IsValidated`` flag to 1. An audit log is written on
    both success and failure.

    :param merchant_email: The email of the merchant account to validate.
    :param request: The HTTP request (for current-user extraction and audit logging).
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A dict with a success message.
    :raises HTTPException 404: If the requesting user or merchant is not found.
    :raises HTTPException 403: If the requesting user is not an admin.
    """
    # Check if requesting user is Admin.
    current_user = get_current_user(request, db_conn)
    current_user_email = current_user.get('email')
    admin = db_conn.query(UserAccount).filter(
        UserAccount.Email == current_user_email).first()
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    current_user_role = current_user.get('role')
    if not current_user_role or current_user_role.lower() != 'admin':
        write_audit_log(db_conn,
                        eventType=LogEventType.MERCHANT_VALIDATED,
                        success=False,
                        userEmail=current_user_email,
                        device=request.headers.get("user-agent"),
                        ipAddress=request.client.host,
                        description=f"Unauthorized merchant validation attempt for {merchant_email}.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

    # Validate the merchant account.
    merchant = db_conn.query(UserAccount).filter(
        UserAccount.Email == merchant_email).first()
    if not merchant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    merchant.IsValidated = True
    db_conn.commit()
    write_audit_log(db_conn,
                    eventType=LogEventType.MERCHANT_VALIDATED,
                    success=True,
                    userEmail=current_user_email,
                    device=request.headers.get("user-agent"),
                    ipAddress=request.client.host,
                    description=f"Merchant account validated.")

    return {"message": f"Merchant has been successfully validated."}


@router.get("/logs")
async def get_logs(
    request: Request,
    user_email: str = None,
    event_type: str = None,
    skip: int = 0,
    limit: int = 100,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = "desc",
    db_conn: Session = Depends(get_db)
):
    """Return logs to an admin user"""
    # Authenticate and authorize admin
    current_user_data = get_current_user(request, db_conn)
    requesting_user_email = current_user_data.get('email')

    admin_user = db_conn.query(UserAccount).filter(
        UserAccount.Email == requesting_user_email).first()
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not identify the requesting user.")

    user_role = db_conn.query(AccountRole).join(UserAccountRole, AccountRole.RoleID ==
                                                UserAccountRole.RoleID).filter(UserAccountRole.UserID == admin_user.UserID).first()

    if not user_role or user_role.RoleName.lower() != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to view logs.")

    SORT_FIELD_MAP = {
        "logID":       AuditLog.LogID,
        "eventType":   AuditLog.EventType,
        "success":     AuditLog.Success,
        "userEmail":   AuditLog.UserEmail,
        "ipAddress":   AuditLog.IPAddress,
        "createdAt":   AuditLog.CreatedAt,
        "device":      None,
        "description": None,
    }

    query = db_conn.query(AuditLog)

    if user_email:
        query = query.filter(AuditLog.UserEmail.ilike(f"%{user_email}%"))
    if event_type:
        query = query.filter(AuditLog.EventType == event_type)

    total_count = query.count()

    sort_col = SORT_FIELD_MAP.get(sort_by) if sort_by else None
    if sort_col is not None:
        order_fn = asc if (sort_order or "desc").lower() == "asc" else desc
        order_clause = order_fn(sort_col)
    else:
        order_clause = AuditLog.CreatedAt.desc()

    logs = query.order_by(order_clause).offset(skip).limit(limit).all()

    result = []

    for log in logs:
        result.append({
            "logID": log.LogID,
            "eventType": log.EventType,
            "success": log.Success,
            "userEmail": log.UserEmail,
            "ipAddress": log.IPAddress,
            "device": log.Device,
            "description": log.Description,
            "createdAt": log.CreatedAt,
        })

    return {
        "logs": result,
        "total": total_count
    }


@router.get("/admin-dashboard/active-account-analytics")
async def get_active_account_analytics(request: Request, db_conn: Session = Depends(get_db)):
    """Return counts of active standard-user accounts in the past month and week."""
    _confirm_admin(request, db_conn)
    prev_month = datetime.now() - timedelta(days=30)
    prev_week = datetime.now() - timedelta(days=7)

    accounts_past_month = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccountRole.UserID == UserAccount.UserID)
        .join(AccountRole, AccountRole.RoleID == UserAccountRole.RoleID)
        .filter(AccountRole.RoleName == "standard_user")
        .join(AuditLog, AuditLog.UserEmail == UserAccount.Email)
        .filter(AuditLog.CreatedAt >= prev_month)
        .distinct()
        .count()
    )

    accounts_past_week = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccountRole.UserID == UserAccount.UserID)
        .join(AccountRole, AccountRole.RoleID == UserAccountRole.RoleID)
        .filter(AccountRole.RoleName == "standard_user")
        .join(AuditLog, AuditLog.UserEmail == UserAccount.Email)
        .filter(AuditLog.CreatedAt >= prev_week)
        .distinct()
        .count()
    )

    return ActiveAccountAnalytics(
        past_month=accounts_past_month,
        past_week=accounts_past_week,
    )


@router.get("/admin-dashboard/active-merchant-analytics")
async def get_active_merchant_analytics(request: Request, db_conn: Session = Depends(get_db)):
    """Return counts of active merchant accounts in the past month and week."""
    _confirm_admin(request, db_conn)
    prev_month = datetime.now() - timedelta(days=30)
    prev_week = datetime.now() - timedelta(days=7)

    merchants_past_month = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccountRole.UserID == UserAccount.UserID)
        .join(AccountRole, AccountRole.RoleID == UserAccountRole.RoleID)
        .filter(AccountRole.RoleName == "merchant")
        .join(AuditLog, AuditLog.UserEmail == UserAccount.Email)
        .filter(AuditLog.CreatedAt >= prev_month)
        .distinct()
        .count()
    )

    merchants_past_week = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccountRole.UserID == UserAccount.UserID)
        .join(AccountRole, AccountRole.RoleID == UserAccountRole.RoleID)
        .filter(AccountRole.RoleName == "merchant")
        .join(AuditLog, AuditLog.UserEmail == UserAccount.Email)
        .filter(AuditLog.CreatedAt >= prev_week)
        .distinct()
        .count()
    )

    return ActiveMerchantAnalytics(
        past_month=merchants_past_month,
        past_week=merchants_past_week,
    )


@router.get("/admin-dashboard/recent-reports-generated-analytics")
async def get_reports_generated_analytics(request: Request, db_conn: Session = Depends(get_db)):
    """Return counts of health reports generated in the past month and week."""
    _confirm_admin(request, db_conn)
    prev_month = datetime.now() - timedelta(days=30)
    prev_week = datetime.now() - timedelta(days=7)

    reports_past_month = (
        db_conn.query(HealthData)
        .filter(HealthData.CreatedAt >= prev_month)
        .count()
    )

    reports_past_week = (
        db_conn.query(HealthData)
        .filter(HealthData.CreatedAt >= prev_week)
        .count()
    )

    return RecentReportsGeneratedAnalytics(
        past_month=reports_past_month,
        past_week=reports_past_week,
    )


@router.get("/admin-dashboard/pending-merchants-analytics")
async def get_pending_merchant_analytics(request: Request, db_conn: Session = Depends(get_db)):
    """Return the number of merchant accounts awaiting validation."""
    _confirm_admin(request, db_conn)

    pending_merchants = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccountRole.UserID == UserAccount.UserID)
        .join(AccountRole, AccountRole.RoleID == UserAccountRole.RoleID)
        .filter(
            AccountRole.RoleName == "merchant",
            UserAccount.IsValidated == False,
        )
        .distinct()
        .count()
    )

    return PendingMerchantAnalytics(
        amount=pending_merchants,
    )


@router.get("/admin-dashboard/predictions-distinct-years")
async def get_predictions_distinct_years(request: Request, db_conn: Session = Depends(get_db)):
    """Return a sorted list of distinct years in which predictions exist."""
    _confirm_admin(request, db_conn)
    query = db_conn.query(
        extract("year", Prediction.CreatedAt).label("year")
    ).distinct().order_by(desc("year")).all()
    return [row._asdict() for row in query]


@router.get("/admin-dashboard/ave-risk-series/{year}")
async def get_average_risk_series(year: int, request: Request, db_conn: Session = Depends(get_db)):
    """
    Return monthly average risk probabilities (stroke, diabetes, CVD) for a given year.

    :param year: The calendar year to aggregate risk data for (e.g. 2025).
    :param request: The HTTP request object (used for admin authentication).
    :param db_conn: Database session provided by the FastAPI dependency.
    :return: A list of dicts, each with ``date`` (YYYY-MM) and average ``stroke``,
             ``diabetes``, ``cvd`` values.
    """
    _confirm_admin(request, db_conn)

    year_start = datetime(year, 1, 1)
    year_end = datetime(year+1, 1, 1)

    query = db_conn.query(
        func.to_char(Prediction.CreatedAt, "YYYY-MM").label('date'),
        func.avg(Prediction.StrokeChance).label('stroke'),
        func.avg(Prediction.DiabetesChance).label('diabetes'),
        func.avg(Prediction.CVDChance).label('cvd'),
    ).filter(
        Prediction.CreatedAt > year_start,
        Prediction.CreatedAt < year_end
    ).group_by("date").order_by("date").all()

    return [row._asdict() for row in query]


@router.get("/admin-dashboard/login-activity/{timespanInDays}")
async def get_login_activity(timespanInDays: int, request: Request, db_conn: Session = Depends(get_db)):
    """Return daily login event counts over the specified number of days."""
    _confirm_admin(request, db_conn)

    start_date = datetime.now() - timedelta(days=timespanInDays)

    query = db_conn.query(
        func.count(AuditLog.EventType).label("total"),
        func.to_char(AuditLog.CreatedAt, "YYYY-MM-DD").label('date'),
    ).filter(
        AuditLog.EventType == LogEventType.LOGIN,
        AuditLog.CreatedAt > start_date,
    ).group_by("date").order_by("date").all()

    return [row._asdict() for row in query]


@router.get("/admin-dashboard/unvalidated-account-analytics")
async def get_unvalidated_account_analytics(request: Request, db_conn: Session = Depends(get_db)):
    """Return the number of standard-user accounts that have not been validated."""
    _confirm_admin(request, db_conn)

    unvalidated_accounts = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccountRole.UserID == UserAccount.UserID)
        .join(AccountRole, AccountRole.RoleID == UserAccountRole.RoleID)
        .filter(
            AccountRole.RoleName == "standard_user",
            UserAccount.IsValidated == False,
        )
        .count()
    )

    return UnvalidatedAccountsAnalytic(
        amount=unvalidated_accounts,
    )


@router.get("/admin-dashboard/user-analytics")
async def get_user_analytics(request: Request, db_conn: Session = Depends(get_db)):
    """Return aggregated counts of total, standard, patient-only, and merchant accounts."""
    _confirm_admin(request, db_conn)

    account_total = db_conn.query(UserAccount).filter(
        UserAccount.IsValidated == True).count()

    patient_total = db_conn.query(Patient).filter(
        Patient.UserID == None).count()
    merchant_total = (
        db_conn.query(UserAccount)
        .join(UserAccountRole, UserAccount.UserID == UserAccountRole.UserID)
        .join(AccountRole, UserAccountRole.RoleID == AccountRole.RoleID)
        .filter(
            AccountRole.RoleName == "merchant",
            UserAccount.IsValidated == True
        )
        .count())

    return AdminUserAnalytics(
        total_accounts=account_total,
        total_standard=(account_total - merchant_total),
        total_patients=patient_total,
        total_merchants=merchant_total,
    )


def _confirm_admin(request: Request, db_conn: Session):
    """Verify the requesting user has an admin role; raises 403/404 otherwise."""
    user = get_current_user(request, db_conn)
    admin = db_conn.query(UserAccount).filter(
        UserAccount.Email == user["email"]).first()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Impermissible action.")

    if not user["role"] or user["role"].lower() != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Impermissible action.")

@router.get("/clinics")
async def get_clinics(db_conn: Session = Depends(get_db)):
    """Returns a list of all clinics."""

    clinics = db_conn.query(Clinic).order_by(Clinic.ClinicName).all()

    result = []

    for clinic in clinics:
        result.append({
            "id": clinic.ClinicID if clinic else None,
            "name": clinic.ClinicName if clinic else None,
        })

    return result
