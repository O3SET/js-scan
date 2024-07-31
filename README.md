# js-scan
js安全审查工具

python开发版本3.9

安装依赖:

pip install -r .\requirements.txt

npm install esprima


使用教程：

扫描目录并生成 JSON 报告：

python scanner.py --dir path/to/dir --format json --output report.json

扫描单个文件并生成 XML 报告：

python scanner.py --file path/to/file.js --format xml --output report.xml

扫描目录并生成 HTML 报告：

python scanner.py --dir path/to/dir --format html --output report.html
