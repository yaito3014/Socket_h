# Overview

ようこそ、ここは、ライブラリのポータルドキュメントです。

---
# Words

| 単語   | 意味                                                         |
| ---- | ---------------------------------------------------------- |
| ソケット | 通信可能なオブジェクトを指す(TCPSocketなど)                                |
| データ型 | is_standard_layout\<T>を満たす型と、is_cross_convertable\<T>を満たす型 |
| バイト列 | uint8_tが並んでいる配列のこと                                         |

---
# Headers

| ヘッダファイル                      | 説明                           | 対応状況 | ソース        |
| ---------------------------- | :--------------------------- | :--: | ---------- |
| [Socket.h](Socket/Socket.md) | 基本的なソケット通信を提供するヘッダー          |  o   | [Source]() |
| [Packet.h](Packet/Packet.md) | データ型とバイト列の相互変換を提供するヘッダー      |  o   | [Source]() |
| [AES128.h](AES128/AES128.md) | AESによる暗号化を提供するヘッダー           |  o   | [Source]() |
| [MultiWordInt.h]()           | 多倍長整数を提供するヘッダー               |  x   | [Source]() |
| [ModInt.h]()                 | MultiWordIntを用いた合同式を提供するヘッダー |  x   | [Source]() |
| [ECDSA.h]()                  | ECDSAによる認証を提供するヘッダー          |  x   | [Source]() |
