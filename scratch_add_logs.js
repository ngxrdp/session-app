const fs = require('fs');
let s = fs.readFileSync('d:/tg/final app/telegram-web/bootstrapIm-CN5TTab5.js', 'utf8');

s = s.replace('function ce(){', 'function ce(){console.log("[DEBUG] ce() START, current P():", P());');
s = s.replace('function le(){', 'function le(){console.log("[DEBUG] le() START, L(\'signIn\'):", L("signIn"), "L(\'signQR\'):", L("signQR"));');
s = s.replace('async function h(){', 'async function h(){console.log("[DEBUG] h() START");');

fs.writeFileSync('d:/tg/final app/telegram-web/bootstrapIm-CN5TTab5.js', s);
console.log('Modified bootstrapIm successfully');
