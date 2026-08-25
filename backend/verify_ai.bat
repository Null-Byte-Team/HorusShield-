@echo off
REM HorusShield AI System - Quick Verification Script
REM Run this to verify all AI components are working correctly

echo.
echo ╔════════════════════════════════════════════════════╗
echo ║  HorusShield AI - System Verification             ║
echo ╚════════════════════════════════════════════════════╝
echo.

cd /d "F:\HorusShield_2_0_v4-3\HorusShield_v43\backend"

echo Running verification tests...
echo.

REM Test 1: Check Python
echo [1/4] Checking Python installation...
C:\Users\yassi_674n3yg\AppData\Local\Programs\Python\Python311\python.exe --version
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found!
    goto :end
)
echo.

REM Test 2: Check AI modules
echo [2/4] Checking AI modules...
C:\Users\yassi_674n3yg\AppData\Local\Programs\Python\Python311\python.exe -c "from ai.anomaly_detector import AnomalyDetector; from ai.threat_classifier import ThreatClassifier; from ai.attack_predictor import AttackPredictor; print('✓ All ML models imported')"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: AI modules failed to import!
    goto :end
)
echo.

REM Test 3: Check dependencies
echo [3/4] Checking dependencies...
C:\Users\yassi_674n3yg\AppData\Local\Programs\Python\Python311\python.exe -c "import sklearn; import pandas; import numpy; import joblib; import flask; print('✓ All dependencies available')"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Dependencies missing!
    goto :end
)
echo.

REM Test 4: Check models
echo [4/4] Checking pre-trained models...
if exist "ai\models\anomaly_detector.joblib" (
    echo ✓ Anomaly detector model found
) else (
    echo ! Anomaly detector model not found - will auto-train on startup
)
if exist "ai\models\threat_classifier.joblib" (
    echo ✓ Threat classifier model found
) else (
    echo ! Threat classifier model not found - will auto-train on startup
)
if exist "ai\models\attack_predictor.joblib" (
    echo ✓ Attack predictor model found
) else (
    echo ! Attack predictor model not found - will auto-train on startup
)
echo.

echo ╔════════════════════════════════════════════════════╗
echo ║  ✅ VERIFICATION COMPLETE - SYSTEM READY          ║
echo ╚════════════════════════════════════════════════════╝
echo.
echo To start the application, run:
echo   C:\Users\yassi_674n3yg\AppData\Local\Programs\Python\Python311\python.exe app.py
echo.
goto :end

:end
pause
