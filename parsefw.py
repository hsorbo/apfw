import struct

f = open('7.4.2.basebinary', 'rb')
buf = f.read()
f.close()

offset = 0
parsed_last_header = False

while not parsed_last_header:
	header = buf[offset:offset+32]

	magic = header[0:14]
	assert magic == 'APPLE-FIRMWARE'

	print '[Header at offset 0x%08x]' % offset

	product_id = struct.unpack('>I', header[16:20])[0]
	print 'ProductId: 0x%08x' % product_id

	version_id = struct.unpack('>I', header[20:24])[0]
	print 'VersionId: 0x%08x' % version_id

	flags = struct.unpack('>I', header[24:28])[0]
	print '    Flags: 0x%08x' % flags

	unknown = struct.unpack('>I', header[28:32])[0]
	print '  Unknown: 0x%08x' % unknown

	print

	if flags & 2 != 0:
		parsed_last_header = True

	offset += len(header)

print 'Last header ended at 0x%08x' % offset
