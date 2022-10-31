@REM Build for Visual Studio compiler. vcvarsall.bat must be in path.
@set OUT_DIR=Release
@set OUT_EXE=libpeer.dll
@set INCLUDES=/I "C:\libzmq\include" /I "include"
@set SOURCES=src\peer.c src\peer_md5sum.c
@set LIBS=/LIBPATH:C:\libzmq\lib zyre.lib czmq.lib libzmq-v142-mt-4_3_4.lib libsodium.lib
mkdir %OUT_DIR%
cl /GS /GL /analyze- /W3 /Gy /Zc:wchar_t /Zi /Gm- /O2 /Zc:inline /fp:precise /WX- /Zc:forScope /Gd /Oy- /Oi /nologo /Zi /MD /EHsc /wd4005 /DWIN32 /D__WINDOWS__ %INCLUDES% /D UNICODE /D _UNICODE /D_USRDLL /D_WINDLL %SOURCES% /Fo%OUT_DIR%/ /link %LIBS% /DLL /OUT:%OUT_DIR%/%OUT_EXE%
copy include\*.h C:\libzmq\include\
copy Release\libpeer.dll C:\libzmq\bin\
copy Release\libpeer.lib C:\libzmq\lib\

@set OUT_EXE=peerchat.exe
@set SOURCES=examples\chat\chat.c
@set LIBS=/LIBPATH:Release libpeer.lib /LIBPATH:C:\libzmq\lib zyre.lib czmq.lib libzmq-v142-mt-4_3_4.lib libsodium.lib
cl /GS /GL /analyze- /W3 /Gy /Zc:wchar_t /Zi /Gm- /O2 /Zc:inline /fp:precise /WX- /Zc:forScope /Gd /Oy- /Oi /nologo /Zi /MD /EHsc /wd4005 /DWIN32 /D__WINDOWS__ %INCLUDES% /D UNICODE /D _UNICODE %SOURCES% /Fe%OUT_DIR%/%OUT_EXE% /Fo%OUT_DIR% /link %LIBS%
copy Release\peerchat.exe C:\libzmq\bin\