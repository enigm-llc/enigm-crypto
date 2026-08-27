import {
  createGroupEpoch,
  decryptContent,
  decryptGroupEpoch,
  encryptContent,
  encryptGroupEpoch,
  generateContentKey,
  rotateGroupEpoch,
  utf8,
} from '../src/index.js';

let epoch = createGroupEpoch(utf8('example-group-id'), ['device-a', 'device-b']);
const metadata = encryptGroupEpoch(epoch, 'metadata', utf8('{"name":"Example"}'));
console.log(new TextDecoder().decode(decryptGroupEpoch(epoch, metadata)));

epoch = rotateGroupEpoch(epoch, ['device-a', 'device-b', 'device-c']);
const message = encryptGroupEpoch(epoch, 'message', utf8('new epoch message'));
console.log(new TextDecoder().decode(decryptGroupEpoch(epoch, message)));

const fileKey = generateContentKey();
const fileContext = utf8('example|conversation:42|file:asset-1');
const file = encryptContent(fileKey, utf8('binary payload'), fileContext);
console.log(new TextDecoder().decode(decryptContent(fileKey, file, fileContext)));
