Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\JOEL STACK\OneDrive\Desktop\Trustscan"
WshShell.Run "python manage.py runserver 0.0.0.0:8001", 0, False
