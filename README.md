# timibaby

这是一个一键脚本仓库（由你提供的 `baby.sh` 生成，已重命名为 `timibaby.sh`），支持通过 `curl | bash` 方式安装。

## 1) 创建 GitHub 仓库后，把本仓库文件上传上去

你需要把 `install.sh` 里的 `REPO_DEFAULT` 改成你的 GitHub 用户名/仓库名，例如：

```bash
REPO_DEFAULT="mucis-dark/timibaby"
```

## 2) 一键安装

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/<你的用户名>/timibaby/main/install.sh)
```

> 如果你暂时不想改 `install.sh`，也可以临时指定：
>
> ```bash
> REPO=<你的用户名>/timibaby sudo bash <(curl -fsSL https://raw.githubusercontent.com/<你的用户名>/timibaby/main/install.sh)
> ```

## 3) 运行

```bash
sudo timibaby
# 或
sudo my
sudo MY
```

## 4) 卸载

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/<你的用户名>/timibaby/main/uninstall.sh)
```
