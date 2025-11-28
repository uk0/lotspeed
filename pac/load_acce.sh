#!/bin/bash

# 配置
CONF_FILE="./acce.conf"
PROC_DIR="/proc/lotspeed"

# 1. 检查是否具有 Root 权限
if [ "$(id -u)" != "0" ]; then
   echo "错误: 请使用 sudo 或 root 权限运行此脚本"
   exit 1
fi

# 2. 检查内核模块是否已加载
if [ ! -d "$PROC_DIR" ]; then
    echo "错误: 未找到 $PROC_DIR"
    echo "请先加载内核模块: insmod acce.ko"
    exit 1
fi

# 3. 检查配置文件是否存在
if [ ! -f "$CONF_FILE" ]; then
    echo "错误: 找不到配置文件 $CONF_FILE"
    exit 1
fi

echo "正在从 $CONF_FILE 加载配置..."
echo "---------------------------------"

# 4. 逐行读取并应用配置
while read -r line || [[ -n "$line" ]]; do
    # 去除行首尾空格
    line=$(echo "$line" | xargs)

    # 忽略注释 (#) 和空行
    if [[ $line == \#* ]] || [[ -z "$line" ]]; then
        continue
    fi

    # 解析 Key 和 Value (以 = 分割)
    # awk -F'=' '{print $1}' 获取等号左边，xargs 去除空格
    key=$(echo "$line" | awk -F'=' '{print $1}' | xargs)
    val=$(echo "$line" | awk -F'=' '{print $2}' | xargs | cut -d' ' -f1) # cut确保只取数值部分

    # 检查 Key 是否有效（对应的 proc 文件是否存在）
    target_file="$PROC_DIR/$key"

    if [ -f "$target_file" ]; then
        # 写入参数到内核
        echo "$val" > "$target_file"

        # 验证写入是否成功（可选）
        current_val=$(cat "$target_file")
        if [ "$current_val" == "$val" ]; then
            echo -e " [OK] 设置 \033[32m$key\033[0m = $val"
        else
            echo -e " [FAIL] 设置 $key 失败 (内核当前值: $current_val)"
        fi
    else
        echo -e " [SKIP] 跳过未知参数: $key (模块中不存在此选项)"
    fi

done < "$CONF_FILE"

echo "---------------------------------"
echo "配置加载完成!"