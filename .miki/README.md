# 自动发布元数据

- `manifests/`：APKG 清单，包含身份、数量、大小和 SHA256。
- `reports/`：模板静态检查与安全交互报告。
- `publish-state.json`：资料 family / release / variant 发布状态。

这些文件由发布程序维护。资源分享使用根目录 APKG 和根目录 README 下载入口。

发布工作流在中间的 immutable snapshot commit 中导出根目录清单兼容入口，再生成固定到该 commit 的 `miki-public/index.json`。推送前的最后一个 commit 移除这些临时入口，使 main 的根目录保持整洁。

清单中的 APKG 路径仍相对于仓库根目录。消费者必须使用 feed 中的 commit-pinned `manifestUrl`，不能直接把内部目录中的清单 URL 当作安装入口；旧的固定 commit 下载链接继续有效。
