# nvd-fetch-practice

NVD（National Vulnerability Database）の **CVE API 2.0** から脆弱性情報を自動で収集し、JSON として蓄積するパイプラインです。
サーバーを持たず、**GitHub Actions だけで完結**します。4時間おきに前回からの差分を取得し、結果をこのリポジトリにコミットします。

```
GitHub Actions（4時間おき）
  └─ nvd_fetch.py
       ├─ last_sync.json を読み、前回の取得時刻を確認
       ├─ NVD CVE API 2.0 に「その時刻以降に更新された CVE」を問い合わせ
       ├─ 必要な項目だけに正規化
       └─ output/ に JSON を書き出し、last_sync.json を更新
  └─ output/ と last_sync.json をコミット
```

## 特徴

- **差分取得**：初回だけ全件（約28万件）を取得し、以降は `lastModStartDate` / `lastModEndDate` で更新分だけを取得します
- **API 制約への対応**
  - 日付範囲フィルタの上限（120日）を超える期間は、自動で分割して取得します
  - 403 / 429 / 503 や通信エラーのときは、指数バックオフ（5秒→最大60秒、最大8回）で再試行します
  - API キーの有無に合わせて、リクエスト間隔を自動で調整します（キーあり 0.65秒 / キーなし 6.5秒）
- **GitHub の容量制限への対応**：1ファイル 2万件ごとに分割して、100MB のファイルサイズ上限を避けます
- **依存は `requests` のみ**です

## 出力

### ファイル

| ファイル | 内容 |
|---|---|
| `output/nvd_cves_20260903_074337.json.gz` | 初回の全件取得（2026-09-03 時点）。gzip 圧縮 |
| `output/nvd_cves_YYYYMMDD_HHMMSS_partNNN.json` | 2回目以降の差分。実行ごとに1ファイル以上 |
| `last_sync.json` | 前回の取得時刻（UTC）。次回の差分取得の起点 |

- 初回の全件分だけは、取得時の実装の都合で gzip 圧縮しています。展開には Mac の `gunzip`、Windows の 7-Zip などを使ってください。差分は圧縮していないので、そのまま開けます
- ファイル名の日時は UTC です
- 更新がなかった回は、ファイルを作りません

### レコードの形式

各ファイルは、次の形のオブジェクトを並べた JSON 配列です。

```json
{
  "cve_id": "CVE-2026-104398",
  "published": "2026-10-10T17:16:59.937",
  "last_modified": "2026-10-10T17:16:59.937",
  "description_en": "Deserialization of Untrusted Data vulnerability in ...",
  "cvss_version": "3.1",
  "cvss_score": 9.8,
  "cvss_severity": "CRITICAL",
  "source": "NVD"
}
```

| 項目 | 内容 |
|---|---|
| `cve_id` | CVE ID |
| `published` / `last_modified` | NVD での公開日時 / 最終更新日時 |
| `description_en` | 英語の説明文 |
| `cvss_version` / `cvss_score` / `cvss_severity` | CVSS v3.1（なければ v3.0）の基本値。評価がない場合は `null` |
| `source` | 取得元（現在は常に `NVD`） |

### 利用時の注意

- `output/` は**差分の履歴**です。同じ CVE が更新されるたびに、複数のファイルに現れます。最新の状態が必要な場合は、`cve_id` ごとに `last_modified` が最も新しいものを採用してください
- **CVSS が `null` の CVE が増えています。** NIST は 2026年4月から、NVD の詳細分析（エンリッチメント）を CISA KEV 掲載の脆弱性などに絞る「リスクベース」の運用に切り替えました。それ以外の CVE は「Not Scheduled」として登録だけされ、スコアが付かないことがあります
- 現在は CVSS v3.x のみを抽出しています。v4.0 だけが付与された CVE も `null` になります

## セットアップ（自分の環境で動かす場合）

1. このリポジトリを fork するか、ファイルをコピーします
2. [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) を取得します（無料）
3. リポジトリの **Settings → Secrets and variables → Actions** に、`NVD_API_KEY` として登録します
4. **Settings → Actions → General → Workflow permissions** を **Read and write permissions** にします
5. **Actions → NVD Fetch → Run workflow** で初回を実行します

初回の全件取得は時間がかかります。`last_sync.json` を削除すると、次回は全件取得からやり直しになります。

### ローカルで実行する

```bash
pip install requests
export NVD_API_KEY="your-api-key"   # 未設定でも動きますが、レート制限が厳しくなります
python3 nvd_fetch.py
```

## 実行間隔の変更

`.github/workflows/nvd_fetch.yml` の `cron` で設定しています（UTC 基準）。

```yaml
- cron: '0 */4 * * *'   # UTC 0, 4, 8, 12, 16, 20 時
```

GitHub Actions のスケジュール実行は混雑状況によって数分〜十数分遅れることがあります。

## 構成

```
.
├── .github/workflows/nvd_fetch.yml   # 定期実行とコミット
├── nvd_fetch.py                      # 取得・正規化・保存
├── last_sync.json                    # 前回の取得時刻
└── output/                           # 取得結果
```

## 今後の予定

- **複数ソースの統合**：OSV、CISA KEV カタログなどを取り込み、CVE ID 単位でマージします。NVD の分析縮小を補うのが目的です
- **NVD の分析ステータスの保持**：`vulnStatus`（Analyzed / Not Scheduled など）を記録し、「未分析だからスコアがない」CVE を区別できるようにします
- **CVSS v4.0 への対応**
- **統合済みスナップショットの生成**：差分の履歴から、CVE ごとの最新状態を1つにまとめたファイルを作ります
- **`output/` の整理**：月ごとのサブフォルダ化や、古いファイルのアーカイブを行います。1ディレクトリのファイル数が増えすぎるのを防ぐためです

## データについて

This product uses the NVD API but is not endorsed or certified by the NVD.

脆弱性データの出典は [National Vulnerability Database](https://nvd.nist.gov/)（NIST）です。
