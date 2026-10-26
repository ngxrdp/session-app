const fs = require('fs');
let s = fs.readFileSync('d:/tg/final app/telegram-web/index-xJZhS8vI.js', 'utf8');
const target = 'import.meta.url);e(h)}else{';
const repl = 'import.meta.url);console.log("CALLING e(h)...",e,h);try{e(h);console.log("e(h) CALLED SUCCESSFULLY");}catch(err){console.error("e(h) FAILED:",err);}}else{';
if (s.includes(target)) {
  s = s.replace(target, repl);
  fs.writeFileSync('d:/tg/final app/telegram-web/index-xJZhS8vI.js', s);
  console.log('SUCCESS');
} else {
  console.log('NOT FOUND');
}
