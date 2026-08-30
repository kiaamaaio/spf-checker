# spf-checker

ドメインの SPF レコードを表示し、指定した IP アドレスがそのドメインの送信元として
認可されているかを判定する CLI ツールです。

## 実行例

### Help

```
spf-checker help
```

```
spf-checker help list
```

### List

SPF レコードを項目ごとに整形して表示します。

```
spf-checker list -domain example.com
```

### Check

IP アドレスが SPF レコードで認可されているかを判定します。

```
spf-checker check -domain github.com -ipaddr 192.30.252.1
```

`-recursive` を付けると `include` / `redirect` / `a` / `mx` を辿って評価します。
付けない場合、これらの項目は評価されず警告として報告されます。

```
spf-checker check -domain github.com -ipaddr 209.85.220.41 -recursive
```

出力例:

```
Domain          : github.com
IP              : 209.85.220.41
Record          : v=spf1 ip4:192.30.252.0/22 include:_netblocks.google.com ... ~all
Result          : pass
Matched         : ip4:209.85.128.0/17 (in the record of _netblocks.google.com)
DNS Lookups     : 2
```

## 判定結果と終了ステータス

`Result` は RFC 7208 の評価結果です。

| Result | 意味 |
| --- | --- |
| `pass` | 認可されている |
| `fail` | 明示的に拒否されている (`-all` など) |
| `softfail` | 認可されていない (`~all`) |
| `neutral` | 判断しない (`?all`、または `all` が無い) |
| `none` | SPF レコードが無い |
| `permerror` | レコードの誤りや DNS ルックアップ上限超過 |
| `temperror` | 一時的な DNS エラー |

終了ステータス:

| コード | 意味 |
| --- | --- |
| 0 | `pass` |
| 1 | `pass` 以外の判定 |
| 2 | 引数エラー (ドメイン名や IP アドレスが不正) |
| 3 | レコードを取得・評価できなかった |

## オプション

| オプション | 対象 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `-domain` | list / check | - | 対象ドメイン |
| `-ipaddr` | check | - | 判定する IP アドレス |
| `-recursive` | check | `false` | `include` / `redirect` / `a` / `mx` を辿る |
| `-timeout` | list / check | `10s` | DNS ルックアップのタイムアウト (`0` で無制限) |

## 制限事項

- マクロ展開 (`%{i}` など) には未対応です。該当する項目は警告を出して読み飛ばします。
- `ptr` メカニズムには未対応です (RFC 7208 でも非推奨)。
- `exp=` 修飾子は解析しますが、説明文の取得は行いません。
- DNS ルックアップ数は RFC 7208 4.6.4 に従い 10 回で打ち切り、`permerror` とします。
