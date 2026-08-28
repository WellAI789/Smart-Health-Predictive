"""FastAPI application entry point for the Smart Health Predictive API.

Includes router modules for health predictions, authentication, user
management, and admin operations. CORS is configured from environment
variable ``CORS_ORIGINS`` or a default set of development origins.
"""
import os

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .routers import health_prediction, authentication, users, admin

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "https://smart-health-predictive-test.onrender.com",
    "https://wellai.app"
]
ENV_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
ORIGINS = DEFAULT_ORIGINS + [
    origin for origin in ENV_ORIGINS if origin not in DEFAULT_ORIGINS
]

app = FastAPI()

STATIC_DIR = Path(__file__).resolve().parent / "static"

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Health-check endpoint; returns a simple greeting."""
    return {"message": "Hello World"}

app.include_router(health_prediction.router)
app.include_router(authentication.router)
app.include_router(users.router)
app.include_router(admin.router)
