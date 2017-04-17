# -*- mode: python -*-

block_cipher = None


a = Analysis(['fibratus\\cli.py'],
             pathex=[],
             binaries=[],
             datas=[('schema.yml', '.')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries + [('msvcp140.dll', 'C:\\Windows\\System32\\msvcp140.dll', 'BINARY'),
                        ('vcruntime140.dll', 'C:\\Windows\\System32\\vcruntime140.dll', 'BINARY')],
          a.zipfiles,
          a.datas,
          name='fibratus',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          icon=None)
