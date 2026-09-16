const { copyFileSync } = require('node:fs');
for (const file of ['index.html', 'styles.css']) copyFileSync(`src/${file}`, `dist/${file}`);
