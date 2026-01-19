import argparse
import sys
import glibc_utmp

# オプションや引数の処理
# 引数でファイルのパスを受け取り、filepathに格納する
ap = argparse.ArgumentParser()
ap.add_argument("filepath", help="処理するファイルのパス")
args = ap.parse_args()

try:
    # 引数で指定されたファイルを読み込む
    with open(args.filepath, "rb") as f:
        data = f.read()
except Exception as e:
    # ファイルを読み込めなかった場合はエラーメッセージを出力して終了する
    print(e)
    sys.exit(1)

# glibc_utmpモジュールでdataをパースする
utmp = glibc_utmp.GlibcUtmp.from_bytes(data)

# 文字列型の属性のNULLバイト以降を削除する
for record in utmp.records:
    record.line = record.line.split("\x00")[0]
    record.id = record.id.split("\x00")[0]
    record.user = record.user.split("\x00")[0]
    record.host = record.host.split("\x00")[0]

# lastコマンドに合わせて時系列の新しい順にログイン履歴を出力する。
for record in reversed(utmp.records):
    print(f"ut_type: {record.ut_type.name}")

    # ut_typeがrun_lvlの場合はランレベルを出力し、それ以外の場合はpidを出力する
    if record.ut_type == glibc_utmp.GlibcUtmp.EntryType.run_lvl:
        # ランレベルが0の場合はpidはNULLバイトであるため0と出力し、
        # それ以外の場合はpidをランレベルの文字に変換して出力する
        if record.pid == 0:
            print(f"runlevel: 0")
        else:
            print(f"runlevel: {chr(record.pid)}")
    else:
        print(f"pid: {record.pid}")

    print(f"line: {record.line}")
    print(f"id: {record.id}")
    print(f"user: {record.user}")
    print(f"host: {record.host}")
    print(f"exit: {record.exit}")
    print(f"session: {record.session}")
    print(f"tv: {record.tv.sec}.{record.tv.usec}")
    print(f"addr_v6: {record.addr_v6}")
    print()
