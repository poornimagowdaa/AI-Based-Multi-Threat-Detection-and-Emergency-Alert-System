# AI-Based Multi-Threat Detection and Emergency Alert System

## Overview

The AI-Based Multi-Threat Detection and Emergency Alert System is an intelligent CCTV surveillance framework designed to detect multiple emergency situations in real time using Artificial Intelligence and Deep Learning. The system continuously monitors surveillance footage and automatically detects three major threats: **Fall**, **Fire**, and **Violence**.

Upon detecting a threat, the system classifies its severity as **Minor**, **Major**, or **Critical**, captures evidence frames, stores incident details in a SQLite database, and automatically sends emergency notifications through **SMS**, **Email**, and **Voice Call** to the appropriate emergency contacts based on predefined alert rules.

This project demonstrates how AI-powered surveillance can improve public safety by reducing response time and enabling automated emergency assistance.

---

## Features

- Real-time CCTV video monitoring
- Fall detection using computer vision
- Fire detection using deep learning
- Violence detection using deep learning
- Severity classification (Minor, Major, Critical)
- Automatic evidence frame extraction
- SQLite database integration
- JSON-based event and coordinate management
- Automated SMS alerts
- Automated Email alerts with evidence images
- Automated Voice Call alerts
- Interactive surveillance dashboard
- Real-time event logging
- Emergency contact management

---

## Threat Detection Workflow

```
Input Video
      │
      ▼
Frame Extraction
      │
      ▼
Frame Preprocessing
      │
      ▼
Threat Detection
 ┌───────────────┐
 │ Fall Detection│
 │ Fire Detection│
 │Violence Detect│
 └───────────────┘
      │
      ▼
Severity Classification
      │
      ▼
Evidence Collection
      │
      ▼
Database Storage
      │
      ▼
SMS + Email + Voice Call Alerts
```

---

## Technologies Used

### Programming Language

- Python

### Deep Learning

- TensorFlow
- Keras
- YOLOv8

### Computer Vision

- OpenCV
- MediaPipe

### Database

- SQLite

### APIs & Services

- Twilio SMS API
- Twilio Voice API
- Gmail SMTP
- OpenStreetMap (OSRM)

### Libraries

- NumPy
- Pandas
- Matplotlib
- Requests
- IPyWidgets

---

## Project Structure

```text
AI-Based-Multi-Threat-Detection-and-Emergency-Alert-System/

│── Project.ipynb
│── README.md
│── requirements.txt
│── LICENSE

│── Dataset/
│   ├── smart_surveillance.db
│   ├── fall_coordinates.json
│   ├── fire_coordinates.json
│   ├── violence_coordinates.json
│   ├── fall_events.json
│   ├── fire_events.json
│   ├── violence_events.json
│   ├── Evidence/
│   └── Results/

│── screenshots/

│── datasets/
│   └── README.md
```

---

## Alert Rules

| Threat | Minor | Major | Critical |
|---------|-------|-------|----------|
| Fall | Family | Family | Family + Hospital |
| Fire | No Alert | Fire Station + Hospital | Fire Station + Hospital |
| Violence | No Alert | No Alert | Police + Hospital |

---

## Dataset

This project uses publicly available datasets for:

- Fall Detection
- Fire Detection
- Violence Detection

The datasets are not included in this repository due to their size. Download links and placement instructions are available in the `datasets` folder.

---

## Results

The developed system is capable of:

- Detecting Fall, Fire, and Violence in real time.
- Classifying threat severity.
- Capturing evidence frames.
- Logging incidents into SQLite.
- Automatically sending SMS alerts.
- Sending Email notifications with evidence images.
- Initiating emergency voice calls.
- Supporting real-time surveillance monitoring.

---

## Future Enhancements

- Multi-camera surveillance support
- Cloud database integration
- Mobile application
- Live dashboard deployment
- Face recognition integration
- Weapon detection
- Suspicious activity detection

---

## Author

**Poornima Rangegowda**

M.Sc. Data Science  
REVA University
