#!/usr/bin/env python3
"""
DoctorG On-Device Scam SMS Classifier Training Script (English / Hindi / Hinglish)
Generates `scam_sms_classifier.tflite` ready to place in `app/src/main/assets/`.

Input Vector (12 float32 lexical/intent features matching ScamSmsClassifier.kt):
 0: kyc_keywords_ratio
 1: otp_pin_request
 2: urgency_threat_score
 3: digital_arrest_terms
 4: courier_customs_terms
 5: lottery_prize_terms
 6: job_task_terms
 7: electricity_bill_terms
 8: has_url
 9: has_short_or_suspicious_tld
10: has_phone_number_cta
11: has_currency_amount

Usage:
    pip install numpy tensorflow
    python3 ml/train_scam_sms_classifier.py --output app/src/main/assets/scam_sms_classifier.tflite
"""

import argparse
import numpy as np
import tensorflow as tf


def build_scam_dataset(num_samples: int = 3000, seed: int = 108):
    rng = np.random.default_rng(seed)
    x = np.zeros((num_samples, 12), dtype=np.float32)
    y = np.zeros((num_samples, 1), dtype=np.float32)

    half = num_samples // 2
    for i in range(half):
        # Legitimate SMS (bank transaction alert, normal OTP without sharing CTA, personal text)
        x[i, 11] = rng.choice([0.0, 1.0], p=[0.6, 0.4])
        x[i, 8] = rng.choice([0.0, 1.0], p=[0.85, 0.15])
        y[i, 0] = 0.0

    for i in range(half, num_samples):
        scam_type = i % 6
        x[i, 2] = rng.uniform(0.5, 1.0)  # urgency
        if scam_type == 0:
            x[i, 0] = 1.0
            x[i, 8] = 1.0
            x[i, 9] = 1.0
        elif scam_type == 1:
            x[i, 1] = 1.0
            x[i, 10] = 1.0
        elif scam_type == 2:
            x[i, 3] = 1.0
            x[i, 10] = 1.0
        elif scam_type == 3:
            x[i, 4] = 1.0
            x[i, 8] = 1.0
            x[i, 9] = 1.0
        elif scam_type == 4:
            x[i, 5] = 1.0
            x[i, 11] = 1.0
        else:
            x[i, 6] = 1.0
            x[i, 11] = 1.0
            x[i, 8] = 1.0
        y[i, 0] = 1.0

    perm = rng.permutation(num_samples)
    return x[perm], y[perm]


def main():
    parser = argparse.ArgumentParser(description="Train DoctorG Scam SMS TFLite model")
    parser.add_argument(
        "--output",
        default="app/src/main/assets/scam_sms_classifier.tflite",
        help="Output .tflite path",
    )
    args = parser.parse_args()

    x, y = build_scam_dataset()
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(12,), name="sms_features"),
        tf.keras.layers.Dense(24, activation="relu"),
        tf.keras.layers.Dense(12, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.fit(x, y, epochs=12, batch_size=32, validation_split=0.2, verbose=1)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()
    with open(args.output, "wb") as f:
        f.write(tflite_model)
    print(f"Saved DoctorG Scam SMS TFLite model to {args.output} ({len(tflite_model)} bytes)")


if __name__ == "__main__":
    main()
