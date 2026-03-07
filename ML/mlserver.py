import joblib
import pandas as pd
from fastapi import FastAPI

app = FastAPI()

# load model
model = joblib.load("smartshield_model.pkl")
protocol_encoder = joblib.load("protocol_encoder.pkl")
category_encoder = joblib.load("category_encoder.pkl")


@app.get("/")
def home():
    return {"status": "SmartShield ML running"}


@app.post("/predict")
def predict(data: dict):

    df = pd.DataFrame([{
        "protocol": data["protocol"],
        "packet_count": data["packet_count"],
        "avg_packet_size": data["avg_packet_size"],
        "flow_duration": data["flow_duration"],
        "packets_per_second": data["packets_per_second"],
        "bytes_per_second": data["bytes_per_second"]
    }])

    prediction = model.predict(df)

    category = category_encoder.inverse_transform(prediction)[0]

    return {"category": category}