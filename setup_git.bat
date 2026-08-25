@echo off
echo Initializing Git repository for HorusShield 2.0...
git init
git add .gitignore
git add backend\
git add HorusShield_UI.html
git add HorusShield.spec
git add README.md
git add build_exe.bat
git add run.bat
git add icon.ico
git add installer\
git status
echo.
echo Ready! Now run:
echo   git commit -m "HorusShield 2.0 — Initial commit"
echo   git remote add origin https://github.com/YOUR_USERNAME/HorusShield.git
echo   git push -u origin main
pause
