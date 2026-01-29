# timibaby

这是一个一键脚本仓库（由你提供的 `baby.sh` 生成，已重命名为 `timibaby.sh`），支持通过 `curl | bash` 方式安装。

## 1) 安装

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/chinahch/timibaby/main/install.sh)
```

> 说明：请先确保你仓库里的 `install.sh` 已把 `REPO_DEFAULT` 设置为：
>
> ```bash
> REPO_DEFAULT="chinahch/timibaby"
> ```

## 2) 运行

```bash
sudo timibaby
# 或
sudo my
sudo MY
```

## 3) 卸载

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/chinahch/timibaby/main/uninstall.sh)
```

## 4) 手动查看脚本（可选）

```bash
curl -fsSL https://raw.githubusercontent.com/chinahch/timibaby/main/timibaby.sh | less
```
