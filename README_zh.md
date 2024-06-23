# hk4e 检查绕过

绕过某个动漫游戏的 version.dll 和反作弊检查。

基于 [SteamAPICheckBypass](https://github.com/oureveryday/Steam-API-Check-Bypass/) 修改。

## 编译

* 使用 Visual Studio 2022 编译。

## 使用方法

### 方法 1 

* 将 `Release_dlls` 中的文件放置于游戏 exe 同目录下
* 将原始的 RSA 补丁 `version.dll` 重命名为 `rsapatch.dll` 并放置于游戏 exe 同目录下
* 将RSA 补丁 `version.dll` 放置于游戏 exe 同目录下

## 依赖

* <https://github.com/Xpl0itR/VersionShim>

## bug

如果您发现任何bug，请在 Github 上提交issue
