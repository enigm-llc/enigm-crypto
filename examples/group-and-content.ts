import {
  createGroupEpoch,
  decryptContent,
  decryptGroupEpoch,
  equal,
  encryptContent,
  encryptGroupEpoch,
  generateContentKey,
  rotateGroupEpoch,
  utf8,
} from '@enigm/crypto';

let epoch = createGroupEpoch(utf8('example-group-id'), ['device-a', 'device-b']);
const expectedMetadata = utf8('{"name":"Example"}');
const metadata = encryptGroupEpoch(epoch, 'metadata', expectedMetadata);
if (!equal(decryptGroupEpoch(epoch, metadata), expectedMetadata)) {
  throw new Error('Group metadata round-trip failed.');
}

epoch = rotateGroupEpoch(epoch, ['device-a', 'device-b', 'device-c']);
const expectedMessage = utf8('new epoch message');
const message = encryptGroupEpoch(epoch, 'message', expectedMessage);
if (!equal(decryptGroupEpoch(epoch, message), expectedMessage)) {
  throw new Error('Group message round-trip failed.');
}

const fileKey = generateContentKey();
const fileContext = utf8('example|conversation:42|file:asset-1');
const expectedFile = utf8('binary payload');
const file = encryptContent(fileKey, expectedFile, fileContext);
if (!equal(decryptContent(fileKey, file, fileContext), expectedFile)) {
  throw new Error('Content round-trip failed.');
}
process.stdout.write('group and content round-trips verified\n');
