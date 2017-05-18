import sys
from Crypto.Cipher import ARC4

encrypted = [
    {'name': 'ConnectionString', 'adr': 0xf610, 'len': 0xff},
    {'name': 'ProxyString', 'adr': 0xf510, 'len': 0xff},
    {'name': 'Password', 'adr': 0xf4ec, 'len': 0x20},
    {'name': 'HostId', 'adr': 0xf4c4, 'len': 0x10},
    {'name': 'MutexName', 'adr': 0xf4b8, 'len': 0x8},
    {'name': 'InstallPath', 'adr': 0xf434, 'len': 0x80},
    {'name': 'StartupKeyName1', 'adr': 0xf420, 'len': 0x10},
    {'name': 'StartupKeyName2', 'adr': 0xf3f8, 'len': 0x26},
    {'name': 'KeyLoggerFileName', 'adr': 0xf374, 'len': 0x80},
    {'name': 'BoolSettingsByte', 'adr': 0xf370, 'len': 0x3},
    {'name': 'ConnectionType', 'adr': 0xf36c, 'len': 0x3}
]

# Open the file
file_handle = open(sys.argv[1])

# BuilderEncryptionKey is at offset 0xf4d8
file_handle.seek(0xf4d8, 0)

# Read the RC4 key
key = file_handle.read(16)

for cipher in encrypted:
  rc4 = ARC4.new(key)
  file_handle.seek(cipher['adr'])
  data = file_handle.read(cipher['len'])
  val = rc4.decrypt(data).split('\x00')[0]
  print "%s: %s" % (cipher['name'], val)

