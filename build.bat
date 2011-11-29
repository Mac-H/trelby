del /a /q winbuild
mkdir winbuild
xcopy src\* winbuild\
xcopy * winbuild\
xcopy /i resources winbuild\dist\resources

cd winbuild
python -OO setup.py py2exe

copy vcredist_x86.exe dist
copy names.txt.gz dist
copy sample.trelby dist
copy manual.html dist
copy fileformat.txt dist
copy LICENSE dist
copy dict_en.dat.gz dist
nsis.bat

move /y setup*exe .. 
move /y dist ..\dist

cd ..
del /a /q winbuild
