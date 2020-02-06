from netzob.all import *

a = PCAPImporter.readFile("neuron5.pcapng", bpfFilter="dst port 7009").values()

fields = [
  Field(0xfd, name='SOF'),
  Field(Raw(nbBytes=1), name='type'),
  Field()
]

b = Symbol(fields, messages = a[:500])

c = Format.clusterByKeyField(b, fields[1])

# Format.splitStatic(c[b'01'].fields[2], mergeAdjacentStaticFields=False)

# d = c[b'01'].fields[2]

# d.fields[0].name = 'id'
# d.fields[1].name = 'src'
# d.fields[2].name = 'dst'

# Format.mergeFields(d.fields[3], d.fields[4])
# Format.mergeFields(d.fields[3], d.fields[4])

# d.fields[3].name = 'params'
# d.fields[4].name = 'EOF'

imu_fields = [
    Field(0xfd, name='SOF'),
    Field(0x09, name='type'),
    Field(Raw(nbBytes=1), name='id'),
    Field(Raw(nbBytes=1), name='src'),
    Field(Raw(nbBytes=31), name="imu"),
    Field(Raw(nbBytes=1), name="crc"),
    Field(0xfe, name="EOF"),
    Field()
]

imu = Symbol(imu_fields, messages = c[b'09'].messages)
imu.addEncodingFunction(TypeEncodingFunction(HexaString))

print(list(EntropyMeasurement.measure_values_entropy(imu_fields[4].getValues())))

#print(imu)
