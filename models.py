from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import LargeBinary

db = SQLAlchemy()


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image_data = db.Column(LargeBinary)
    original_filename = db.Column(db.String(120))
