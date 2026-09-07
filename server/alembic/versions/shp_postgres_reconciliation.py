"""Reconcile existing PostgreSQL database with current SHP schema.

This migration is PostgreSQL-specific and reconciles the existing database
at revision 8184ee23453b with the current SQLAlchemy models.
"""

from alembic import op
import sqlalchemy as sa


revision = "shp_postgres_reconciliation"
down_revision = "8184ee23453b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade existing PostgreSQL database to current SHP schema."""

    # ------------------------------------------------------------------
    # 1. Create tables that are missing from the existing database.
    # ------------------------------------------------------------------

    op.create_table(
        "Clinic",
        sa.Column("ClinicID", sa.Integer(), nullable=False),
        sa.Column("ClinicName", sa.String(length=255), nullable=True),
        sa.Column(
            "CreatedAt",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("ClinicID"),
        sa.UniqueConstraint("ClinicName"),
    )

    op.create_table(
        "Patient",
        sa.Column("PatientID", sa.Integer(), nullable=False),
        sa.Column("UserID", sa.Integer(), nullable=True),
        sa.Column("GivenNames", sa.String(length=255), nullable=True),
        sa.Column("FamilyName", sa.String(length=255), nullable=True),
        sa.Column("Gender", sa.Integer(), nullable=True),
        sa.Column("Weight", sa.Numeric(5, 2), nullable=True),
        sa.Column("Height", sa.Numeric(5, 2), nullable=True),
        sa.Column("DateOfBirth", sa.Date(), nullable=True),
        sa.Column(
            "CreatedAt",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.Column("MaritalStatus", sa.Integer(), nullable=True),
        sa.Column("WorkingStatus", sa.Integer(), nullable=True),
        sa.Column("Race", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["UserID"], ["UserAccount.UserID"]),
        sa.PrimaryKeyConstraint("PatientID"),
    )

    op.create_table(
        "AuditLog",
        sa.Column("LogID", sa.Integer(), nullable=False),
        sa.Column("EventType", sa.String(length=50), nullable=False),
        sa.Column("Success", sa.Boolean(), nullable=False),
        sa.Column("UserID", sa.Integer(), nullable=True),
        sa.Column("UserEmail", sa.String(length=255), nullable=True),
        sa.Column("IPAddress", sa.String(length=40), nullable=True),
        sa.Column("Device", sa.String(length=255), nullable=True),
        sa.Column("Description", sa.Text(), nullable=True),
        sa.Column(
            "CreatedAt",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(["UserID"], ["UserAccount.UserID"]),
        sa.PrimaryKeyConstraint("LogID"),
    )

    op.create_table(
        "PasswordResetToken",
        sa.Column("TokenID", sa.Integer(), nullable=False),
        sa.Column("UserID", sa.Integer(), nullable=False),
        sa.Column("Token", sa.String(length=999), nullable=False),
        sa.Column("ExpiresAt", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["UserID"], ["UserAccount.UserID"]),
        sa.PrimaryKeyConstraint("TokenID"),
    )

    op.create_table(
        "UserPatientAccess",
        sa.Column("UserID", sa.Integer(), nullable=False),
        sa.Column("PatientID", sa.Integer(), nullable=False),
        sa.Column(
            "CreatedAt",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(["UserID"], ["UserAccount.UserID"]),
        sa.ForeignKeyConstraint(["PatientID"], ["Patient.PatientID"]),
        sa.PrimaryKeyConstraint("UserID", "PatientID"),
    )

    op.create_table(
        "PatientRequestToken",
        sa.Column("TokenID", sa.Integer(), nullable=False),
        sa.Column("MerchantID", sa.Integer(), nullable=False),
        sa.Column("PatientID", sa.Integer(), nullable=False),
        sa.Column("Token", sa.String(length=999), nullable=False),
        sa.Column("ExpiresAt", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["MerchantID"], ["UserAccount.UserID"]),
        sa.ForeignKeyConstraint(["PatientID"], ["Patient.PatientID"]),
        sa.PrimaryKeyConstraint("TokenID"),
    )

    # ------------------------------------------------------------------
    # 2. Add current columns to existing tables.
    # ------------------------------------------------------------------

    op.add_column(
        "UserAccount",
        sa.Column("ClinicID", sa.Integer(), nullable=True),
    )

    op.create_foreign_key(
        "UserAccount_ClinicID_fkey",
        "UserAccount",
        "Clinic",
        ["ClinicID"],
        ["ClinicID"],
    )

    op.add_column(
        "HealthData",
        sa.Column("PatientID", sa.Integer(), nullable=True),
    )

    op.add_column(
        "HealthData",
        sa.Column("Stroke", sa.Integer(), nullable=True),
    )

    op.add_column(
        "HealthData",
        sa.Column("Race", sa.Integer(), nullable=True),
    )

    # ------------------------------------------------------------------
    # 3. Create Patient records for existing standard users.
    #
    # Existing standard users:
    #   151742614  Audrey Young
    #   68849883   Steven Wallace
    #   1424460213 Adam Peake
    #   938812579  Keith Hart
    # ------------------------------------------------------------------

    op.execute(
        sa.text(
            """
            INSERT INTO "Patient"
                ("PatientID", "UserID", "GivenNames", "FamilyName",
                 "Gender", "Weight", "Height", "DateOfBirth")
            VALUES
                (1, 151742614, 'Audrey', 'Young',
                 1, 65.00, 170.00, '1994-01-01'),
                (2, 68849883, 'Steven', 'Wallace',
                 1, 48.50, 150.00, '2001-01-01'),
                (3, 1424460213, 'Adam', 'Peake',
                 1, 83.70, 160.00, '1982-01-01'),
                (4, 938812579, 'Keith', 'Hart',
                 1, 70.00, 175.00, '1990-01-01')
            """
        )
    )

    # ------------------------------------------------------------------
    # 4. Preserve existing merchant-to-patient access relationships.
    # ------------------------------------------------------------------

    op.execute(
        sa.text(
            """
            INSERT INTO "UserPatientAccess" ("UserID", "PatientID")
            SELECT DISTINCT "MerchantID",
                CASE
                    WHEN "UserID" = 151742614 THEN 1
                    WHEN "UserID" = 68849883 THEN 2
                    WHEN "UserID" = 1424460213 THEN 3
                    WHEN "UserID" = 938812579 THEN 4
                END
            FROM "HealthData"
            WHERE "MerchantID" IS NOT NULL
            """
        )
    )

    # ------------------------------------------------------------------
    # 5. Map every existing HealthData record to its Patient.
    # ------------------------------------------------------------------

    op.execute(
        sa.text(
            """
            UPDATE "HealthData"
            SET "PatientID" =
                CASE
                    WHEN "UserID" = 151742614 THEN 1
                    WHEN "UserID" = 68849883 THEN 2
                    WHEN "UserID" = 1424460213 THEN 3
                    WHEN "UserID" = 938812579 THEN 4
                END
            WHERE "UserID" IS NOT NULL
            """
        )
    )

    # ------------------------------------------------------------------
    # 6. Convert Alcohol BOOLEAN -> INTEGER.
    #
    # Preserve:
    #   FALSE -> 0
    #   TRUE  -> 1
    # ------------------------------------------------------------------

    op.alter_column(
        "HealthData",
        "Alcohol",
        existing_type=sa.Boolean(),
        type_=sa.Integer(),
        postgresql_using='"Alcohol"::integer',
        existing_nullable=True,
    )

    # ------------------------------------------------------------------
    # 7. Remove obsolete columns from HealthData.
    # ------------------------------------------------------------------

    op.drop_column("HealthData", "UserID")
    op.drop_column("HealthData", "MerchantID")

    # ------------------------------------------------------------------
    # 8. Remove obsolete UserAccount column.
    # ------------------------------------------------------------------

    op.drop_column("UserAccount", "FullName")

    # ------------------------------------------------------------------
    # 9. Remove obsolete tables.
    # ------------------------------------------------------------------

    op.drop_table("RolePermission")
    op.drop_table("Permission")
    op.drop_table("TestTable")


def downgrade() -> None:
    """Downgrade is intentionally not supported for this data migration."""
    raise NotImplementedError(
        "Downgrade is not supported for the PostgreSQL reconciliation migration."
    )
