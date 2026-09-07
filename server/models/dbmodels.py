from sqlalchemy import Column, Integer, String, DateTime, text, Boolean, Numeric, ForeignKey, Text, Date
from sqlalchemy.orm import declarative_base, relationship
import enum

MARITAL_STATUS_OPTIONS = {
    0: 'Single',
    1: 'Married',
    2: 'Widow',
    3: 'Divorced'
}

WORKING_STATUS_OPTIONS = {
    0: 'Unemployed',
    1: 'Homemaker',
    2: 'Student',
    3: 'Working',
    4: 'Retired',
}

RACE_OPTIONS = {
    0: 'Malay',
    1: 'Chinese',
    2: 'Indian',
    3: 'Other'
}

SMOKER_OPTIONS = {
    0: 'No',
    1: 'Yes',
    2: 'Former smoker'
}

ALCOHOL_OPTIONS = {
    0: 'Regular',
    1: 'Occasional',
    2: 'Non-drinker'
}

Base = declarative_base()


class UserAccount(Base):
    __tablename__ = 'UserAccount'
    UserID = Column(Integer, primary_key=True)
    ClinicID = Column(Integer, ForeignKey("Clinic.ClinicID"), nullable=True)

    Email = Column(String(255), unique=True)
    PasswordHash = Column(String(255), nullable=False)
    PhoneNumber = Column(String(20))
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))
    IsValidated = Column(Boolean, default=False)
    TokenVersion = Column(Integer, nullable=False, default=0)

    clinic = relationship("Clinic", back_populates="users")
    userRoles = relationship("UserAccountRole", back_populates="user")
    patients = relationship("Patient", back_populates="user")
    patient_access = relationship("UserPatientAccess", back_populates="user")

    def __init__(self, clinicID, email, password_hash, phone_number):
        self.ClinicID = clinicID
        self.Email = email
        self.PasswordHash = password_hash
        self.PhoneNumber = phone_number

    def __repr__(self):
        return f'UserAccount(UserID={self.UserID}, ClinicID={self.ClinicID}, \
            Email={self.Email}, PasswordHash={self.PasswordHash}, \
            Phone={self.PhoneNumber}, Created={self.CreatedAt}, \
            IsValidated={self.IsValidated})'


class Clinic(Base):
    __tablename__ = 'Clinic'
    ClinicID = Column(Integer, primary_key=True)
    ClinicName = Column(String(255), unique=True)
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))

    users = relationship("UserAccount", back_populates="clinic")

    def __repr__(self):
        return f'Clinic(ClinicID={self.ClinicID}, ClinicName={self.ClinicName}, \
            CreatedAt={self.CreatedAt})'


class AccountRole(Base):
    __tablename__ = 'AccountRole'
    RoleID = Column(Integer, primary_key=True)
    RoleName = Column(String(100))

    userRoles = relationship("UserAccountRole", back_populates="role")

    def __init__(self, RoleName):
        self.RoleName = RoleName

    def __repr__(self):
        return f'AccountRole(RoleID={self.RoleID}, RoleName={self.RoleName})'


class UserAccountRole(Base):
    __tablename__ = 'UserAccountRole'
    RoleID = Column(Integer, ForeignKey(
        "AccountRole.RoleID"), primary_key=True)
    UserID = Column(Integer, ForeignKey(
        "UserAccount.UserID"), primary_key=True)
    AssignedAt = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    user = relationship("UserAccount", back_populates="userRoles")
    role = relationship("AccountRole", back_populates="userRoles")

    def __init__(self, RoleID, UserID):
        self.RoleID = RoleID
        self.UserID = UserID

    def __repr__(self):
        return f'UserAccountRole(RoleID={self.RoleID}, UserID={self.UserID}, \
                AssignedAt={self.AssignedAt})'


class Patient(Base):
    __tablename__ = 'Patient'
    PatientID = Column(Integer, primary_key=True)
    UserID = Column(Integer, ForeignKey(UserAccount.UserID))

    GivenNames = Column(String(255))
    FamilyName = Column(String(255))
    Gender = Column(Integer)
    Weight = Column(Numeric(5, 2))
    Height = Column(Numeric(5, 2))
    DateOfBirth = Column(Date)
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))
    MaritalStatus = Column(Integer)
    WorkingStatus = Column(Integer)
    Race = Column(Integer)

    user = relationship("UserAccount", back_populates="patients")
    health_records = relationship("HealthData", back_populates="patient")
    user_access = relationship("UserPatientAccess", back_populates="patient")

    def __init__(
            self,
            user_id,
            given_names,
            family_name,
            gender,
            weight,
            height,
            date_of_birth,
            marital_status=None,
            working_status=None,
            race=None
    ):
        self.UserID = user_id
        self.GivenNames = given_names
        self.FamilyName = family_name
        self.Gender = gender
        self.Weight = weight
        self.Height = height
        self.DateOfBirth = date_of_birth
        self.MaritalStatus = marital_status
        self.WorkingStatus = working_status
        self.race = race

    def __repr__(self):
        return f'Patient(PatientID={self.PatientID}, UserID={self.UserID}, givenNames={self.GivenNames}, \
        familyName={self.FamilyName}, gender={self.Gender}, weight={self.Weight}, height={self.Height}, \
        dateOfBirth={self.DateOfBirth}, Created={self.CreatedAt})'

    def get_marital_status(self):
        """Returns marital status as a string."""
        return MARITAL_STATUS_OPTIONS.get(self.MaritalStatus)

    def get_working_status(self):
        """Returns working status as a string."""
        return WORKING_STATUS_OPTIONS.get(self.WorkingStatus)

    def get_race(self):
        """Returns race as a string."""
        return RACE_OPTIONS.get(self.Race)

    def set_marital_status(self, status: int | str):
        """Sets the value of the marital status and will convert a string
        to the matching integer."""
        if isinstance(status, str):
            self.MaritalStatus = next(
                (k for k, v in MARITAL_STATUS_OPTIONS.items() if v == status), None)
        else:
            self.MaritalStatus = status

    def set_working_status(self, status: int | str):
        """Sets the value of the working status and will convert a string
        to the matching integer."""
        if isinstance(status, str):
            self.WorkingStatus = next(
                (k for k, v in WORKING_STATUS_OPTIONS.items() if v == status), None)
        else:
            self.WorkingStatus = status

    def set_race(self, race: int | str):
        """Sets the value of the race and will convert a string
        to the matching integer."""
        if isinstance(race, str):
            self.Race = next(
                (k for k, v in RACE_OPTIONS.items() if v == race), None)
        else:
            self.Race = race


class UserPatientAccess(Base):
    __tablename__ = 'UserPatientAccess'
    UserID = Column(Integer, ForeignKey(UserAccount.UserID), primary_key=True)
    PatientID = Column(Integer, ForeignKey(
        Patient.PatientID), primary_key=True)
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))

    user = relationship("UserAccount", back_populates="patient_access")
    patient = relationship("Patient", back_populates="user_access")

    def __init__(self, user_id, patient_id):
        self.UserID = user_id
        self.PatientID = patient_id

    def __repr__(self):
        return f'UserPatientAccess(UserID={self.UserID}, PatientID={self.PatientID}, \
            Created={self.CreatedAt})'


class HealthData(Base):
    __tablename__ = 'HealthData'
    # Keys
    HealthDataID = Column(Integer, primary_key=True)
    PatientID = Column(Integer, ForeignKey(Patient.PatientID))

    # Variables
    Age = Column(Integer)
    WeightKilograms = Column(Numeric(5, 2))
    HeightCentimetres = Column(Numeric(5, 2))
    Gender = Column(Boolean)
    BloodGlucose = Column(Numeric(5, 2))
    APHigh = Column(Numeric(5, 2))
    APLow = Column(Numeric(5, 2))
    HighCholesterol = Column(Boolean)
    HyperTension = Column(Boolean)
    HeartDisease = Column(Boolean)
    Diabetes = Column(Boolean)
    Alcohol = Column(Integer)
    SmokingStatus = Column(Integer)
    MaritalStatus = Column(Integer)
    WorkingStatus = Column(Integer)
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))
    Stroke = Column(Integer)
    Race = Column(Integer)

    patient = relationship("Patient", back_populates="health_records")
    predictions = relationship("Prediction", back_populates="health_data")
    recommendations = relationship(
        "Recommendation", back_populates="health_data")

    def __init__(self, PatientID, age, weight, height, gender, bloodGlucose, ap_hi,
                 ap_lo, highCholesterol, hyperTension, heartDisease,
                 diabetes, alcohol, smoker, maritalStatus, workingStatus, stroke, race):
        self.PatientID = PatientID
        self.Age = age
        self.WeightKilograms = weight
        self.HeightCentimetres = height
        self.Gender = gender
        self.BloodGlucose = bloodGlucose
        self.APHigh = ap_hi
        self.APLow = ap_lo
        self.HighCholesterol = highCholesterol
        self.HyperTension = hyperTension
        self.HeartDisease = heartDisease
        self.Diabetes = diabetes
        self.Alcohol = alcohol
        self.SmokingStatus = smoker
        self.MaritalStatus = maritalStatus
        self.WorkingStatus = workingStatus
        self.Stroke = stroke
        self.Race = race

    def __repr__(self):
        return f'HealthData(HealthDataID = {self.HealthDataID}, UserID={self.UserID}, age={self.Age}, weight={self.WeightKilograms}, \
            height={self.HeightCentimetres}, gender={self.Gender}, bloodGlucose={self.BloodGlucose}, \
            ap_hi={self.APHigh}, ap_lo={self.APLow}, highCholesterol={self.HighCholesterol}, \
            hyperTension={self.HyperTension}, heartDisease={self.HeartDisease}, \
            diabetes={self.Diabetes}, alcohol={self.Alcohol}, smoker={self.SmokingStatus}, \
            maritalStatus={self.MaritalStatus}, workingStatus={self.WorkingStatus}, race={self.Race}, Created={self.CreatedAt},  Stroke={self.Stroke} )'


class Prediction(Base):

    __tablename__ = 'Prediction'
    # Keys
    PredictionID = Column(Integer, primary_key=True)
    HealthDataID = Column(Integer, ForeignKey(HealthData.HealthDataID))

    # Variables
    StrokeChance = Column(Numeric(4, 2))
    DiabetesChance = Column(Numeric(4, 2))
    CVDChance = Column(Numeric(4, 2))
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))

    health_data = relationship("HealthData", back_populates="predictions")

    def __init__(self, healthDataID, strokeChance, diabetesChance, CVDChance):
        self.HealthDataID = healthDataID
        self.StrokeChance = strokeChance
        self.DiabetesChance = diabetesChance
        self.CVDChance = CVDChance

    def __repr__(self):
        return f'Prediction(PredictionID = {self.PredictionID}, HealthDataID = {self.HealthDataID}, StrokeChance = {self.StrokeChance}, \
        DiabetesChance = {self.DiabetesChance}, CVDChance = {self.CVDChance}, Created={self.CreatedAt})'


class UserAccountValidationToken(Base):
    __tablename__ = 'UserAccountValidationToken'
    UserID = Column(Integer, ForeignKey('UserAccount.UserID'),
                    primary_key=True, nullable=False)
    ValidationToken = Column(String(999), nullable=False)
    ExpiresAt = Column(DateTime, nullable=False)

    def __init__(self, user_id, validation_token, expires_at):
        self.UserID = user_id
        self.ValidationToken = validation_token
        self.ExpiresAt = expires_at

    def __repr__(self):
        return f'UserAccountValidationToken(UserID={self.UserID}, \
            ValidationToken={self.ValidationToken}, ExpiresAt={self.ExpiresAt})'


class Recommendation(Base):
    __tablename__ = 'Recommendation'

    # Keys
    RecommendationID = Column(Integer, primary_key=True)
    HealthDataID = Column(Integer, ForeignKey('HealthData.HealthDataID'))

    # Content
    ExerciseRecommendation = Column(Text)
    DietRecommendation = Column(Text)
    LifestyleRecommendation = Column(Text)
    DietToAvoidRecommendation = Column(Text)
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))

    def __init__(self, healthDataID, exerciseRecommendation, dietRecommendation, lifestyleRecommendation, dietToAvoidRecommendation=None):
        self.HealthDataID = healthDataID
        self.ExerciseRecommendation = exerciseRecommendation
        self.DietRecommendation = dietRecommendation
        self.LifestyleRecommendation = lifestyleRecommendation
        self.DietToAvoidRecommendation = dietToAvoidRecommendation

    health_data = relationship("HealthData", back_populates="recommendations")

    def __repr__(self):
        return (f'Recommendation(RecommendationID={self.RecommendationID}, '
                f'HealthDataID={self.HealthDataID}, '
                f'CreatedAt={self.CreatedAt})')


class LogEventType(str, enum.Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    REGISTRATION = "REGISTRATION"
    EMAIL_VALIDATION = "EMAIL_VALIDATION"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    ROLE_CHANGED = "ROLE_CHANGED"
    ACCOUNT_DELETED = "ACCOUNT_DELETED"
    MERCHANT_VALIDATED = "MERCHANT_VALIDATED"
    PREDICTION_REQUEST = "PREDICTION_REQUEST"
    DATA_IMPORT = "DATA_IMPORT"
    FAILED_LOGIN_ATTEMPT = "FAILED_LOGIN_ATTEMPT"
    RESET_PASSWORD_REQUEST = "RESET_PASSWORD_REQUEST"
    PASSWORD_RESET = "PASSWORD_RESET"
    USER_PROFILE_UPDATED = "USER_PROFILE_UPDATED"
    PATIENT_PROFILE_UPDATED = "PATIENT_PROFILE_UPDATED"


class AuditLog(Base):
    __tablename__ = 'AuditLog'
    LogID = Column(Integer, primary_key=True)
    EventType = Column(String(50), nullable=False)
    Success = Column(Boolean, nullable=False)
    UserID = Column(Integer, ForeignKey('UserAccount.UserID'))
    UserEmail = Column(String(255))
    IPAddress = Column(String(40))
    Device = Column(String(255))
    Description = Column(Text)
    CreatedAt = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'))

    def __init__(self, eventType, success, userID=None, userEmail=None, ipAddress=None,
                 device=None, description=None):
        self.EventType = eventType
        self.Success = success
        self.UserID = userID
        self.UserEmail = userEmail
        self.IPAddress = ipAddress
        self.Device = device
        self.Description = description

    def __repr__(self):
        return f'AuditLog(LogID={self.LogID}, EventType={self.EventType}, \
                Success={self.Success}, UserID={self.UserID}, \
                CreatedAt={self.CreatedAt})'


class PasswordResetToken(Base):
    __tablename__ = 'PasswordResetToken'
    TokenID = Column(Integer, primary_key=True)
    UserID = Column(Integer, ForeignKey('UserAccount.UserID'),
                    nullable=False)
    Token = Column(String(999), nullable=False)
    ExpiresAt = Column(DateTime, nullable=False)

    def __init__(self, user_id, token, expires_at):
        self.UserID = user_id
        self.Token = token
        self.ExpiresAt = expires_at

    def __repr__(self):
        return f'PasswordResetToken(UserID={self.UserID}, \
            Token={self.Token}, ExpiresAt={self.ExpiresAt})'


class PatientRequestToken(Base):
    __tablename__ = 'PatientRequestToken'

    TokenID = Column(Integer, primary_key=True)
    MerchantID = Column(Integer, ForeignKey(
        'UserAccount.UserID'), nullable=False)
    PatientID = Column(Integer, ForeignKey(
        'Patient.PatientID'), nullable=False)

    Token = Column(String(999), nullable=False)
    ExpiresAt = Column(DateTime, nullable=False)

    def __init__(self, merchant_id, patient_id, token, expires_at):
        self.MerchantID = merchant_id
        self.PatientID = patient_id
        self.Token = token
        self.ExpiresAt = expires_at

    def __repr__(self):
        return f'PatientRequestToken(MerchantID={self.MerchantID}, \
            PatientID={self.PatientID},Token={self.Token}, \
                ExpiresAt={self.ExpiresAt})'
