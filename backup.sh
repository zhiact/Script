#!/bin/bash

# === 配置项 ===
DB_PATH="/Dashboard/data/sqlite.db"
BACKUP_DIR="/backup"
DATE=$(date +%F-%H-%M-%S)
GITHUB_REPO="github.com/zhiact/nezha-backup.git"
GIT_EMAIL="linweihuamail@gmail.com"
GIT_NAME="zhiact"
GITHUB_TOKEN="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"

# === 准备目录 ===
mkdir -p $BACKUP_DIR
cp $DB_PATH $BACKUP_DIR/nezha-$DATE.db
cd $BACKUP_DIR

# === Git 初始化（第一次用）===
if [ ! -d ".git" ]; then
  git init
  git config user.email "$GIT_EMAIL"
  git config user.name "$GIT_NAME"
  git remote add origin https://${GITHUB_TOKEN}@${GITHUB_REPO}
fi

# === 提交并推送 ===
git add .
git commit -m "Backup on $DATE"
git pull --rebase origin master
git push origin master
