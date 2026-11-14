# CTF ツールボックス

ブラウザだけで動く、CTF用の解読・ファイル解析ツールです。

## すぐ使う

`index.html` をダブルクリックすると、ブラウザで開きます。

## フォルダの中身

| ファイル | 役割 |
|---|---|
| `index.html` | 完成品。これだけで動く（下の3つを1つにまとめたもの） |
| `template.html` | 画面（HTML・CSS）と、ボタンを押したときの処理 |
| `core.js` | 変換・暗号のロジック（Base64、シーザー、XOR、ハッシュ、自動解析など） |
| `fcore.js` | ファイル解析のロジック（PNG・JPEG・ZIP・EXIF・LSB など） |
| `build.py` | `template.html` に `core.js` と `fcore.js` を埋め込んで `index.html` を作るスクリプト |
| `test.js` / `t2.js` | `core.js` のテスト |
| `ftest.js` | `fcore.js` のテスト（`samples` の全ファイルを解析） |
| `mksamples.py` | 練習用ファイル（`samples`）を作るスクリプト |
| `samples/` | フラグを隠した練習用ファイル10個 |

## 自分で改造したあと

1. `core.js` / `fcore.js` / `template.html` を編集する
2. ターミナル（コマンドを打つ画面）でこのフォルダに移動して、次を実行する

```
python build.py
```

3. 新しい `index.html` ができるので、ブラウザで開いて確認する

## テストのやり方（Node.js が必要）

```
node test.js
node ftest.js
```

`test.js` は最後に `ALL OK` と出れば成功です。
