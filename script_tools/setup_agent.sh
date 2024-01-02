#!/bin/bash
# vim:ft=sh expandtab sts=4 ts=4 sw=4 nu
# gse agent安装脚本, 仅在节点管理2.0中使用

# DEFAULT DEFINITION
NODE_TYPE=agent

GSE_AGENT_RUN_DIR=/var/run/gse  # 定义 GSE Agent 运行目录
GSE_AGENT_DATA_DIR=/var/lib/gse  # 定义 GSE Agent 数据目录
GSE_AGENT_LOG_DIR=/var/log/gse  # 定义 GSE Agent 日志目录

OS_INFO=""  # 存储操作系统信息
OS_TYPE=""  # 存储操作系统类型
RC_LOCAL_FILE=/etc/rc.d/rc.local  # 初始化启动脚本文件路径
BACKUP_CONFIG_FILES=("procinfo.json")  # 需要备份的配置文件列表

# 收到如下信号或者exit退出时，执行清理逻辑
#trap quit 1 2 3 4 5 6 7 8 10 11 12 13 14 15
trap 'cleanup' HUP INT QUIT ABRT SEGV PIPE ALRM TERM EXIT  # 设置信号处理逻辑
trap 'report_err $LINENO; exit 1; ' ERR  # 设置错误处理逻辑

# 日志记录函数
log ()  {
    local L=INFO D;  D="$(date +%F\ %T)"; echo "$D $L $*" | tee -a "$LOG_FILE"; bulk_report_step_status "$LOG_FILE" "$BULK_LOG_SIZE" ; return 0;
}
# 警告记录函数
warn () {
    local L=WARN D;  D="$(date +%F\ %T)"; echo "$D $L $*" | tee -a "$LOG_FILE"; bulk_report_step_status "$LOG_FILE" "$BULK_LOG_SIZE" ; return 0;
}
# 错误记录函数
err ()  {
    local L=ERROR D; D="$(date +%F\ %T)"; echo "$D $L $*" | tee -a "$LOG_FILE"; bulk_report_step_status "$LOG_FILE" "$BULK_LOG_SIZE" ; return 1;
}
# 致命错误记录函数
fail () {
    local L=ERROR D; D="$(date +%F\ %T)"; echo "$D $L $*" | tee -a "$LOG_FILE"; bulk_report_step_status "$LOG_FILE" "$BULK_LOG_SIZE" URG; exit 1;
}

# 获取CPU架构
# 参数:
#   $1: 用于获取CPU架构信息的命令
# 返回值:
#   0: 成功获取CPU架构信息
#   1: 无法获取CPU架构信息
get_cpu_arch () {
    local cmd=$1
    CPU_ARCH=$($cmd)  # 使用给定命令获取CPU架构信息
    CPU_ARCH=$(echo ${CPU_ARCH} | tr 'A-Z' 'a-z')  # 将CPU架构信息转换为小写

    # 检查CPU架构信息，设置CPU_ARCH变量
    if [[ "${CPU_ARCH}" =~ "x86_64" ]]; then
        return 0  # x86_64 架构
    elif [[ "${CPU_ARCH}" =~ "x86" || "${CPU_ARCH}" =~ ^i[3456]86 ]]; then
        CPU_ARCH="x86"  # x86 32位架构
        return 0
    elif [[ "${CPU_ARCH}" =~ "aarch" ]]; then
        return 0  # ARM架构
    else
        return 1  # 无法识别的CPU架构
    fi
}

# 使用指定命令来获取CPU架构信息，如果获取失败，则尝试下一个命令，直到成功为止
get_cpu_arch "uname -p" || get_cpu_arch "uname -m"  || arch || fail get_cpu_arch "Failed to get CPU arch, please contact the developer."

PKG_NAME=gse_client-linux-${CPU_ARCH}.tgz  # 设置变量PKG_NAME为gse_client-linux-${CPU_ARCH}.tgz

get_os_info () {  # 定义名为get_os_info的函数
    if [ -f "/proc/version" ]; then  # 如果/proc/version文件存在
        OS_INFO="$OS_INFO $(cat /proc/version)"  # 将/proc/version文件的内容附加到变量OS_INFO中
    fi
    if [ -f "/etc/issue" ]; then  # 如果/etc/issue文件存在
        OS_INFO="$OS_INFO $(cat /etc/issue)"  # 将/etc/issue文件的内容附加到变量OS_INFO中
    fi
    OS_INFO="$OS_INFO $(uname -a)"  # 将uname -a的输出附加到变量OS_INFO中
    OS_INFO=$(echo ${OS_INFO} | tr 'A-Z' 'a-z')  # 将OS_INFO中的大写字母转换为小写字母
}

get_os_type () {  # 定义名为get_os_type的函数
    get_os_info  # 调用get_os_info函数
    OS_INFO=$(echo ${OS_INFO} | tr 'A-Z' 'a-z')  # 将OS_INFO中的大写字母转换为小写字母
    if [[ "${OS_INFO}" =~ "ubuntu" ]]; then  # 如果OS_INFO中包含"ubuntu"
        OS_TYPE="ubuntu"  # 设置变量OS_TYPE为ubuntu
        RC_LOCAL_FILE="/etc/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.local
    elif [[ "${OS_INFO}" =~ "centos" ]]; then  # 如果OS_INFO中包含"centos"
        OS_TYPE="centos"  # 设置变量OS_TYPE为centos
        RC_LOCAL_FILE="/etc/rc.d/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.d/rc.local
    elif [[ "${OS_INFO}" =~ "coreos" ]]; then  # 如果OS_INFO中包含"coreos"
        OS_TYPE="coreos"  # 设置变量OS_TYPE为coreos
        RC_LOCAL_FILE="/etc/rc.d/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.d/rc.local
    elif [[ "${OS_INFO}" =~ "freebsd" ]]; then  # 如果OS_INFO中包含"freebsd"
        OS_TYPE="freebsd"  # 设置变量OS_TYPE为freebsd
        RC_LOCAL_FILE="/etc/rc.d/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.d/rc.local
    elif [[ "${OS_INFO}" =~ "debian" ]]; then  # 如果OS_INFO中包含"debian"
        OS_TYPE="debian"  # 设置变量OS_TYPE为debian
        RC_LOCAL_FILE="/etc/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.local
    elif [[ "${OS_INFO}" =~ "suse" ]]; then  # 如果OS_INFO中包含"suse"
        OS_TYPE="suse"  # 设置变量OS_TYPE为suse
        RC_LOCAL_FILE="/etc/rc.d/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.d/rc.local
    elif [[ "${OS_INFO,,}" =~ "hat" ]]; then  # 如果OS_INFO中包含"hat"（不区分大小写）
        OS_TYPE="redhat"  # 设置变量OS_TYPE为redhat
        RC_LOCAL_FILE="/etc/rc.d/rc.local"  # 设置变量RC_LOCAL_FILE为/etc/rc.d/rc.local
    fi
}

check_rc_file () {  # 定义名为check_rc_file的函数
    get_os_type  # 调用get_os_type函数
    if [ -f $RC_LOCAL_FILE ]; then  # 如果RC_LOCAL_FILE文件存在
        return 0  # 返回0
    elif [ -f "/etc/rc.d/rc.local" ]; then  # 否则，如果/etc/rc.d/rc.local文件存在
        RC_LOCAL_FILE="/etc/rc.d/rc.local"  # 设置RC_LOCAL_FILE变量为/etc/rc.d/rc.local
    else  # 否则
        RC_LOCAL_FILE="/etc/rc.local"  # 设置RC_LOCAL_FILE变量为/etc/rc.local
    fi
}

# 清理逻辑：保留本次的LOG_FILE,下次运行时会删除历史的LOG_FILE。
# 保留安装脚本本身
cleanup () {  # 定义名为cleanup的函数
    bulk_report_step_status "$LOG_FILE" "$BULK_LOG_SIZE" URG  # 调用bulk_report_step_status函数并传入参数
    if ! [[ $DEBUG = "true" ]]; then  # 如果DEBUG不等于"true"
        local GLOBIGNORE="$LOG_FILE*"  # 设置本地变量GLOBIGNORE为"$LOG_FILE*"
        rm -vf "$TMP_DIR"/nm.*  # 删除"$TMP_DIR"/nm.*文件
    fi
    exit 0  # 退出脚本并返回0
}

# 打印错误行数信息
report_err () {  # 定义名为report_err的函数
    awk -v LN="$1" -v L="ERROR" -v D="$(date +%F\ %T)" \  # 使用awk命令打印错误行数信息
        'NR>LN-3 && NR<LN+3 { printf "%s %s cmd-return-err %-5d%3s%s\n", D, L, NR, (NR==LN?">>>":""), $0 }' $0  # 在文件$0中打印错误行数信息
}

validate_setup_path () {
    local invalid_path_prefix=(  # 定义不允许的路径前缀数组
        /tmp
        /var
        /etc
        /bin
        /lib
        /lib64
        /boot
        /mnt
        /proc
        /dev
        /run
        /sys
        /sbin
        /root
        /home
    )

    local invalid_path=(  # 定义不允许的路径数组
        /usr
        /usr/bin
        /usr/sbin
        /usr/local/lib
        /usr/include
        /usr/lib
        /usr/lib64
        /usr/libexec
    )

    local p1="${AGENT_SETUP_PATH%/$NODE_TYPE*}"  # 获取AGENT_SETUP_PATH的路径，去除节点类型之后的部分
    local p2="${p1%/gse*}"  # 去除gse之后的部分
    local p

    if [[ "$p1" == "${AGENT_SETUP_PATH}" ]] || [[ "$p2" == "$AGENT_SETUP_PATH" ]]; then  # 如果p1或p2等于AGENT_SETUP_PATH
        fail check_env FAILED "$AGENT_SETUP_PATH is not allowed to install agent"  # 执行fail函数并返回错误信息
    fi

    for p in "${invalid_path[@]}"; do  # 遍历不允许的路径数组
        if [[ "${p2}" == "$p" ]]; then  # 如果p2等于不允许的路径
            fail check_env FAILED "$AGENT_SETUP_PATH is not allowed to install agent"  # 执行fail函数并返回错误信息
        fi
    done

    for p in "${invalid_path_prefix[@]}"; do  # 遍历不允许的路径前缀数组
        if [[ "${p2//$p}" != "$p2" ]]; then  # 如果p2包含不允许的路径前缀
            fail check_env FAILED "$AGENT_SETUP_PATH is not allowed to install agent"  # 执行fail函数并返回错误信息
        fi
    done
}

is_port_listen () {
    local i port

    for i in {0..15}; do  # 循环15次
        sleep 1  # 休眠1秒
        for port in "$@"; do  # 遍历传入的端口列表
            lsof -iTCP:"$port" -sTCP:LISTEN -a -i -P -n -p "$AGENT_PID" && return 0  # 使用lsof命令检查端口是否处于监听状态
        done
    done

    return 1  # 返回1
}

# 判断某个pid是否监听指定的端口列表
# 利用linux内核/proc/<pid>/net/tcp文件中第四列0A表示LISTEN
# 第二列16进制表达的ip和port
is_port_listen_by_pid () {
    local pid regex stime  # 定义本地变量pid、regex、stime
    pid=$1  # 将第一个参数赋值给pid
    shift 1  # 移除第一个参数

    if [ `wc -l /proc/net/tcp |awk '{print $1}'` -le 5000 ];then  # 如果/proc/net/tcp文件的行数小于等于5000
        stime=1  # 设置stime为1
    else  # 否则
        stime=0  # 设置stime为0
    fi

    for i in {0..10}; do  # 循环10次
        echo ------ $i  `date '+%c'`  # 输出当前循环次数和日期时间
        sleep 1  # 休眠1秒
        for port in "$@"; do  # 遍历传入的端口列表
            if [ $stime -eq 1 ];then  # 如果stime等于1
                echo need to sleep 1s  # 输出需要休眠1秒
                sleep 1  # 休眠1秒
            fi

            echo ------ $port  `date '+%c'`  # 输出当前端口和日期时间
            stat -L -c %i /proc/"$pid"/fd/* 2>/dev/null \
                | grep -qwFf - \
                    <( awk -v p="$port" 'BEGIN{ check=sprintf(":%04X0A$", p)} $2$4 ~ check {print $10}' /proc/net/tcp) \
                    && return 0  # 检查pid是否监听指定的端口列表
        done
    done
    return 1  # 返回1
}

is_port_connected_by_pid () {
    local pid port regex  # 定义本地变量pid、port、regex
    pid=$1 port=$2  # 将第一个参数赋值给pid，第二个参数赋值给port

    for i in {0..10}; do  # 循环10次
        sleep 1  # 休眠1秒
        stat -L -c %i /proc/"$pid"/fd/* 2>/dev/null \
            | grep -qwFf - \
                <( awk -v p="$port" 'BEGIN{ check=sprintf(":%04X01$", p)} $3$4 ~ check {print $10}' /proc/net/tcp) \
                && return 0  # 检查pid是否连接到指定端口
    done
    return 1  # 返回1
}

is_connected () {
    local i port=$1  # 定义本地变量i和port，port为传入的第一个参数

    for i in {0..15}; do  # 循环15次
        sleep 1  # 休眠1秒
        lsof -iTCP:"$port" -sTCP:ESTABLISHED -a -i -P -n -p "$AGENT_PID" && return 0  # 使用lsof命令检查指定端口是否处于连接状态
    done

    return 1  # 返回1
}

is_gsecmdline_ok () {
   /bin/gsecmdline -d 1430 -s test  # 运行gsecmdline命令
}

get_pid_by_comm_path () {
    local comm=$1 path=$2  # 定义本地变量comm和path，分别为传入的第一个和第二个参数
    local _pids pids
    local pid
    read -r -a _pids <<< "$(ps --no-header -C "$comm" -o pid | xargs)"  # 通过ps命令获取指定命令的pid列表

    # 如果传入了绝对路径，则进行基于二进制路径的筛选
    if [[ -e "$path" ]]; then  # 如果路径存在
        for pid in "${_pids[@]}"; do  # 遍历pid列表
            if [[ "$(readlink -f "$path")" = "$(readlink -f /proc/"$pid"/exe)" ]]; then  # 检查二进制路径是否匹配
                if ! grep -nEq '^\ +$' <<< "$pid"; then  # 如果pid不为空
                    pids+=("$pid")  # 添加pid到pids数组
                fi
            fi
        done
    else
        pids=("${_pids[@]}")  # 否则直接将pid列表赋值给pids数组
    fi

    echo ${pids[@]}  # 输出pids数组
}

is_process_ok () {
    local proc=${1:-agent}  # 定义本地变量proc，默认为agent
    local gse_master gse_workers
    local gse_master_pids
    gse_master_pids="$( get_pid_by_comm_path gseMaster "$AGENT_SETUP_PATH/bin/gse_${proc}" | xargs)"  # 获取gseMaster的pid
    read -r -a gse_master <<< "$gse_master_pids"  # 读取gseMaster的pid到数组gse_master
    read -r -a gse_workers <<< "$( get_pid_by_comm_path "${proc}Worker" "$AGENT_SETUP_PATH/bin/gse_${proc}" | xargs)"  # 获取${proc}Worker的pid

    if [ "${#gse_master[@]}" -eq 0 ]; then  # 如果gseMaster的pid列表为空
        fail setup_agent FAILED "process check: no gseMaster found. gse_${proc} process abnormal (node type:$NODE_TYPE)"  # 执行fail函数并返回错误信息
    fi

    if [ "${#gse_master[@]}" -gt 1 ]; then  # 如果gseMaster的pid列表长度大于1
        fail setup_agent FAILED "process check: ${#gse_master[@]} gseMaster found. pid($gse_master_pids) gse_${proc} process abnormal (node type:$NODE_TYPE)"  # 执行fail函数并返回错误信息
    fi

    # worker 进程在某些情况下可能不止一个，只要都是一个父进程，多个worker也是正常，不为0即可
    if [ "${#gse_workers[@]}" -eq 0 ]; then  # 如果${proc}Worker的pid列表为空
        fail setup_agent FAILED "process check: ${proc}Worker not found (node type:$NODE_TYPE)"  # 执行fail函数并返回错误信息
    fi
}

is_target_reachable () {
    local ip="$1"  # 定义本地变量ip为传入的第一个参数
    local target_port="$2"  # 定义本地变量target_port为传入的第二个参数
    local ports=()  # 定义本地变量ports为数组
    local _port err timeout_exist

    if [[ $target_port =~ [0-9]+-[0-9]+ ]]; then  # 如果target_port是一个范围
        ports=( $(seq ${target_port//-/ }) )  # 使用seq命令生成端口范围
    else
        ports=( "$target_port" )  # 否则直接将target_port添加到ports数组
    fi

    # 判断timeout命令是否存在
    hash timeout 2>/dev/null
    case $? in
        0) timeout_exist=0 ;;  # 如果timeout命令存在，则timeout_exist为0
        1) timeout_exist=1 ;;  # 否则timeout_exist为1
    esac

    if [[ "${#ports[@]}" -gt 1 ]]; then  # 如果ports数组长度大于1
        local result=0
        for _port in "${ports[@]}"; do  # 遍历ports数组
            if [ "$timeout_exist" -eq 0 ]; then  # 如果timeout命令存在
                timeout 5 bash -c ">/dev/tcp/$ip/$_port"  # 使用timeout命令检查ip和端口的连接
            else
                bash -c ">/dev/tcp/$ip/$_port"  # 否则直接检查ip和端口的连接
            fi
            case $? in
                0) return 0 ;;  # 如果连接成功，返回0
                1) warn check_env -  "connect to upstream server($ip:$target_port) failed: connection refused" && result+=1;;  # 如果连接被拒绝，返回警告信息并result加1
               ## 超时的情况，只要有一个端口是超时的情况，认定为网络不通，不继续监测
                124) warn check_env "connect to upstream server($ip:$target_port) failed: NETWORK TIMEOUT"  && return 1;;  # 如果网络超时，返回警告信息并返回1
            esac
        done
        if [[ "$result" -eq "${#ports[@]}" ]]; then  # 如果result等于ports数组长度
            return 1  # 返回1
        fi
    else
       for _port in "${ports[@]}"; do  # 遍历ports数组
           if [ "$timeout_exist" -eq 0 ]; then  # 如果timeout命令存在
               timeout 5 bash -c ">/dev/tcp/$ip/$_port"  # 使用timeout命令检查ip和端口的连接
           else
               bash -c ">/dev/tcp/$ip/$_port"  # 否则直接检查ip和端口的连接
           fi
           case $? in
               0) return 0 ;;  # 如果连接成功，返回0
               1) warn check_env -  "connect to upstream server($ip:$target_port) failed: connection refused" && return 1 ;;  # 如果连接被拒绝，返回警告信息并返回1
               ## 超时的情况，只要有一个端口是超时的情况，认定为网络不通，不继续监测
               124) warn check_env "connect to upstream server($ip:$target_port) failed: NETWORK TIMEOUT" && return 1 ;;  # 如果网络超时，返回警告信息并返回1
           esac
       done
    fi
}

multi_reachable_ip_check () {
    local target_port="$1"  # 定义本地变量target_port为传入的第一个参数
    shift 1  # 移除第一个参数
    local ips=($@)  # 定义本地变量ips为参数数组
    local result=0  # 定义本地变量result为0
    for ip in "${ips[@]}"; do  # 遍历ips数组
        log check_env - "check if it is reachable to port $target_port of $ip)"  # 记录日志
        if ! is_target_reachable "${ip}" "${target_port}"; then  # 如果不可到达目标
          result+=1  # 结果加1
        fi
    done
    if [[ "${result}" -ge "${#ips[@]}" ]]; then  # 如果结果大于或等于ips数组长度
      fail check_env FAILED "connect to upstream server(${ips[@]})-(${target_port[@]}) failed"  # 执行失败函数并返回错误信息
    fi
}

## network policy check
check_polices_agent_to_upstream () {
    #local pagent_to_proxy_port_policies=(gse_task:48668 gse_data:58625 gse_btsvr:58925 gse_btsvr:10020-10030)
    #local pagent_listen_ports=(gse_agent:60020-60030)

    # 非直连Agent的上级节点是所属管控区域的proxy
    multi_reachable_ip_check "$IO_PORT" "${TASK_SERVER_IP[@]}"  # 检查任务服务器端口是否可到达
    multi_reachable_ip_check "$DATA_PORT" "${DATA_SERVER_IP[@]}"  # 检查数据服务器端口是否可到达
    multi_reachable_ip_check "$FILE_SVR_PORT" "${BT_FILE_SERVER_IP[@]}"  # 检查文件服务器端口是否可到达
    multi_reachable_ip_check "$BT_PORT"-"$TRACKER_PORT" "${BT_FILE_SERVER_IP[@]}"  # 检查BT端口到Tracker端口是否可到达
}

check_polices_pagent_to_upstream () {
    check_polices_agent_to_upstream  # 检查pagent到上游
}

check_polices_proxy_to_upstream () {
    #local proxy_to_server_policies=(gse_task:48668 gse_data:58625 gse_btsvr:58930 gse_btsvr:10020-10030 gse_ops:58725)
    #local proxy_listen_ports=(gse_agent:48668 gse_transit:58625 gse_btsvr:58930 gse_btsvr:58925 gse_btsvr:10020-10030 gse_opts:58725)

    # GSE Proxy 的上级节点可能是 GSE Server(不同的接入点), 也可能是一级Proxy节点
    multi_reachable_ip_check "$IO_PORT" "${TASK_SERVER_IP[@]}"  # 检查任务服务器端口是否可到达
    multi_reachable_ip_check "$DATA_PORT" "${DATA_SERVER_IP[@]}"  # 检查数据服务器端口是否可到达
    multi_reachable_ip_check "$BTSVR_THRIFT_PORT" "${BT_FILE_SERVER_IP[@]}"  # 检查BTSVR THRIFT端口是否可到达
    multi_reachable_ip_check "$BT_PORT" "${BT_FILE_SERVER_IP[@]}"  # 检查BT端口是否可到达
}

pre_view () {
   log PREVIEW - "---- precheck current deployed agent info ----"  # 记录预览信息

   if [[ -f $AGENT_SETUP_PATH/etc/agent.conf ]]; then  # 如果agent配置文件存在
       log PREVIEW - "normalized agent:"  # 记录代理信息
       log PREVIEW - "   setup path: $(readlink -f "${AGENT_SETUP_PATH}"/bin/gse_agent)"  # 记录设置路径
       log PREVIEW - "   process:"  # 记录进程
           lsof -a -d txt -c agentWorker -c gseMaster -a -n "$AGENT_SETUP_PATH"/bin/gse_agent  # 使用lsof命令查看相关进程
       log PREVIEW - "   gsecmdline: $(is_gsecmdline_ok && echo OK || echo NO)"  # 检查gsecmdline命令是否可用
    fi
}

remove_crontab () {
    local tmpcron  # 定义本地变量tmpcron
    tmpcron=$(mktemp "$TMP_DIR"/cron.XXXXXXX)  # 创建临时文件

    # 仅删除关联到安装目录的 crontab，避免多 Agent 互相影响
    crontab -l | grep -v "${AGENT_SETUP_PATH}"  >"$tmpcron"  # 从crontab中排除与安装目录相关的内容并输出到临时文件
    crontab "$tmpcron" && rm -f "$tmpcron"  # 更新crontab并删除临时文件

    # 下面这段代码是为了确保修改的crontab能立即生效
    if pgrep -x crond &>/dev/null; then  # 如果crond进程存在
        pkill -HUP -x crond  # 发送HUP信号给crond进程
    fi
}

setup_startup_scripts () {
    check_rc_file  # 检查rc文件
    local rcfile=$RC_LOCAL_FILE  # 定义本地变量rcfile为RC_LOCAL_FILE

    if [ $OS_TYPE == "ubuntu" ]; then  # 如果操作系统类型为ubuntu
        sed -i "\|\#\!/bin/bash|d" $rcfile  # 删除rc文件中的shebang行
        sed -i "1i \#\!/bin/bash" $rcfile  # 在第一行插入shebang行
    fi
    chmod +x $rcfile  # 添加执行权限

    # 先删后加，避免重复
    sed -i "\|${AGENT_SETUP_PATH}/bin/gsectl|d" $rcfile  # 删除rc文件中与安装目录相关的内容

    echo "[ -f $AGENT_SETUP_PATH/bin/gsectl ] && $AGENT_SETUP_PATH/bin/gsectl start >/var/log/gse_start.log 2>&1" >>$rcfile  # 在rc文件中添加启动命令
}

start_agent () {
    local i p

    "$AGENT_SETUP_PATH"/bin/gsectl start || fail setup_agent FAILED "start gse agent failed"  # 启动gse agent，如果失败则执行失败函数

    sleep 3  # 等待3秒
    is_process_ok agent  # 检查agent进程是否正常
}

remove_proxy_if_exists () {
    local i pids
    local path=${AGENT_SETUP_PATH%/*}/proxy  # 定义变量path为AGENT_SETUP_PATH上级目录下的proxy目录路径

    ! [[ -d $path ]] && return 0  # 如果路径不存在则返回0

    "$path/bin/gsectl" stop  # 停止proxy目录下的gsectl进程

    for p in agent transit btsvr; do  # 遍历agent、transit和btsvr
        for i in {0..10}; do  # 循环10次
            read -r -a pids <<< "$(pidof "$path"/bin/gse_${p})"  # 读取对应进程的PID
            if [ ${#pids[@]} -eq 0 ]; then  # 如果PID数组长度为0
                # 进程已退，继续检查下一个进程
                break  # 跳出循环
            elif [ "$i" == 10 ]; then  # 如果循环次数等于10
                kill -9 "${pids[@]}"  # 强制终止对应的进程
            else
                sleep 1  # 等待1秒
            fi
        done
    done

    rm -rf "$path"  # 移除proxy目录
}

stop_agent () {
    local i pids

    ! [[ -d $AGENT_SETUP_PATH ]] && return 0  # 如果AGENT_SETUP_PATH目录不存在则返回0

    "$AGENT_SETUP_PATH/bin/gsectl" stop  # 停止gsectl进程

    for i in {1..10}; do  # 循环10次
        for pid in $(pidof "${AGENT_SETUP_PATH}"/bin/gse_agent); do  # 获取gse_agent的PID
          # 富容器场景下，会误杀docker里的agent进程，因此需要判断父进程ID是否为1，仅干掉这些进程
          if [[ $(ps  --no-header -o ppid -p $pid) -eq 1 ]]; then  # 如果父进程ID为1
             pids=($pid $(pgrep -P $pid))  # 获取进程PID及其子进程的PID
             break  # 跳出循环
          fi
        done
        if [[ ${#pids[@]} -eq 0 ]]; then  # 如果PID数组长度为0
            log remove_agent SUCCESS 'old agent has been stopped successfully'  # 记录日志
            break  # 跳出循环
        elif [[ $i -eq 10 ]]; then  # 如果循环次数等于10
            kill -9 "${pids[@]}"  # 强制终止对应的进程及其子进程
        else
            sleep 1  # 等待1秒
        fi
    done
}

backup_config_file () {
    local file
    for file in "${BACKUP_CONFIG_FILES[@]}"; do  # 遍历备份配置文件数组
        local tmp_backup_file
        if [ -f "${AGENT_SETUP_PATH}/etc/${file}" ]; then  # 如果配置文件存在
            tmp_backup_file=$(mktemp "${TMP_DIR}"/nodeman_${file}_config.XXXXXXX)  # 创建临时备份文件
            log backup_config_file - "backup $file to $tmp_backup_file"  # 记录备份信息
            cp -rf "${AGENT_SETUP_PATH}"/etc/"${file}" "${tmp_backup_file}"  # 复制配置文件到临时备份文件
            chattr +i "${tmp_backup_file}"  # 添加不可修改属性
        fi
    done
}

recovery_config_file () {
    for file in "${BACKUP_CONFIG_FILES[@]}"; do  # 遍历备份配置文件数组
        local latest_config_file tmp_config_file_abs_path
        time_filter_config_file=$(find "${TMP_DIR}" -ctime -1 -name "nodeman_${file}_config*")  # 根据时间筛选配置文件
        [ -z "${time_filter_config_file}" ] && return 0  # 如果时间筛选文件为空则返回0
        latest_config_file=$(find "${TMP_DIR}" -ctime -1 -name "nodeman_${file}_config*" | xargs ls -rth | tail -n 1)  # 获取最新的配置文件
        chattr -i "${latest_config_file}"  # 移除不可修改属性
        cp -rf "${latest_config_file}" "${AGENT_SETUP_PATH}"/etc/"${file}"  # 复制配置文件到对应目录
        rm -f "${latest_config_file}"  # 移除临时配置文件
        log recovery_config_file - "recovery ${AGENT_SETUP_PATH}/etc/${file} from $latest_config_file"  # 记录恢复配置文件信息
    done
}

remove_agent () {
    log remove_agent - 'trying to stop old agent'  # 记录日志
    stop_agent  # 停止agent

    backup_config_file  # 备份配置文件
    log remove_agent - "trying to remove old agent directory(${AGENT_SETUP_PATH})"  # 记录日志
    cd "${AGENT_SETUP_PATH}"  # 切换到AGENT_SETUP_PATH目录
    for file in `lsattr -R |egrep "i-" |awk '{print $NF}'`;do echo "--- $file" && chattr -i $file ;done  # 移除目录下所有不可修改属性
    cd -  # 切换到上一个工作目录
    rm -rf "${AGENT_SETUP_PATH}"  # 移除AGENT_SETUP_PATH目录

    if [[ "$REMOVE" == "TRUE" ]]; then  # 如果REMOVE变量为TRUE
        log remove_agent DONE "agent removed"  # 记录日志
        exit 0  # 退出脚本
    fi
}

get_config () {
    local filename http_status
    local config=(agent.conf)  # 配置文件数组

    log get_config - "request $NODE_TYPE config file(s)"  # 记录请求配置文件操作

    for filename in "${config[@]}"; do  # 遍历配置文件数组
        tmp_json_body=$(mktemp "$TMP_DIR"/nm.reqbody."$(date +%Y%m%d_%H%M%S)".XXXXXX.json)  # 创建请求体临时文件
        tmp_json_resp=$(mktemp "$TMP_DIR"/nm.reqresp."$(date +%Y%m%d_%H%M%S)".XXXXXX.json)  # 创建响应临时文件
        cat > "$tmp_json_body" <<_OO_
{
    "bk_cloud_id": ${CLOUD_ID},
    "filename": "${filename}",
    "node_type": "${NODE_TYPE}",
    "inner_ip": "${LAN_ETH_IP}",
    "token": "${TOKEN}"
}
_OO_

        http_status=$(http_proxy=$HTTP_PROXY https_proxy=$HTTP_PROXY \
            curl -s -S -X POST --retry 5 -d@"$tmp_json_body" "$CALLBACK_URL"/get_gse_config/ -o "$TMP_DIR/$filename" --silent -w "%{http_code}")  # 发送HTTP POST请求获取配置文件
        rm -f "$tmp_json_body" "$tmp_json_resp"  # 移除临时文件

        if [[ "$http_status" != "200" ]]; then  # 如果HTTP状态码不为200
            fail get_config FAILED "request config $filename failed. request info:$CLOUD_ID,$LAN_ETH_IP,$NODE_TYPE,$filename,$TOKEN. http status:$http_status, file content: $(cat "$TMP_DIR/$filename")"  # 执行失败函数并返回错误信息
        fi
    done
}

setup_agent () {
    log setup_agent START "setup agent. (extract, render config)"  # 记录开始设置agent

    mkdir -p "$AGENT_SETUP_PATH"  # 创建AGENT_SETUP_PATH目录

    cd "$AGENT_SETUP_PATH/.." && tar xf "$TMP_DIR/$PKG_NAME"  # 解压缩PKG_NAME到AGENT_SETUP_PATH的上级目录

    # update gsecmdline under /bin
    cp -fp plugins/bin/gsecmdline /bin/  # 复制gsecmdline到/bin
    # 注意这里 /bin/ 可能是软链
    cp -fp plugins/etc/gsecmdline.conf /bin/../etc/  # 复制gsecmdline.conf到/etc
    chmod 775 /bin/gsecmdline  # 修改gsecmdline权限

    # setup config file
    get_config  # 获取配置文件

    recovery_config_file  # 恢复配置文件

    local config=(agent.conf)  # 配置文件数组
    for f in "${config[@]}"; do  # 遍历配置文件数组
        if [[ -f $TMP_DIR/$f ]]; then  # 如果临时目录下的配置文件存在
            cp -fp "$TMP_DIR/${f}" agent/etc/${f}  # 复制配置文件到agent/etc目录
        else
            fail setup_agent FAILED "agent config file ${f}  lost. please check."  # 执行失败函数并返回错误信息
        fi
    done

    # create dir
    mkdir -p "$GSE_AGENT_RUN_DIR" "$GSE_AGENT_DATA_DIR" "$GSE_AGENT_LOG_DIR"  # 创建目录

    start_agent  # 启动agent

    log setup_agent DONE "gse agent is setup successfully."  # 记录设置agent成功
}

download_pkg () {
    local f http_status path
    local tmp_stdout tmp_stderr curl_pid

    log download_pkg START "download gse agent package from $DOWNLOAD_URL/$PKG_NAME)."  # 记录开始下载agent包

    cd "$TMP_DIR" && rm -f "$PKG_NAME" "agent.conf.$LAN_ETH_IP"  # 切换到TMP_DIR并移除对应文件

    for f in $PKG_NAME; do  # 遍历PKG_NAME列表
        tmp_stdout=$(mktemp "${TMP_DIR}"/nm.curl.stdout_XXXXXXXX)  # 创建临时标准输出文件
        tmp_stderr=$(mktemp "${TMP_DIR}"/nm.curl.stderr_XXXXXXXX)  # 创建临时标准错误文件
        curl --connect-timeout 5 -o "$TMP_DIR/$f" \
                --progress-bar -w "%{http_code}" "$DOWNLOAD_URL/$f" >"$tmp_stdout" 2>"$tmp_stderr" &  # 使用curl下载agent包
        curl_pid=$!

        # 如果curl结束，那么http_code一定会写入到stdout文件
        until [[ -n $http_status ]]; do
            read -r http_status < "$tmp_stdout"  # 读取http状态码
            # 为了上报curl的进度
            log download_pkg DOWNLOADING "$(awk 'BEGIN { RS="\r"; } END { print }' < "$tmp_stderr")"  # 记录下载进度
            sleep 1  # 等待1秒
        done
        rm -f "${tmp_stdout}" "${tmp_stderr}"  # 移除临时文件
        wait "$curl_pid"  # 等待curl进程结束

        # HTTP status 000需要进一步研究
        if [[ $http_status != "200" ]] && [[ "$http_status" != "000" ]]; then  # 如果HTTP状态码不为200且不为000
            fail download_pkg FAILED "file $f download failed. (url:$DOWNLOAD_URL/$f, http_status:$http_status)"  # 执行失败函数并返回错误信息
        fi
    done

    log download_pkg DONE "gse_agent package download succeeded"  # 记录下载成功
    log report_cpu_arch DONE "${CPU_ARCH}"  # 记录CPU架构信息
}

check_deploy_result () {
    # 端口监听状态
    local ret=0  # 返回值初始化为0

    AGENT_PID=$( get_pid_by_comm_path agentWorker "$AGENT_SETUP_PATH/bin/gse_agent" )  # 获取agentWorker进程的PID
    is_port_listen_by_pid "$AGENT_PID" $(seq "$BT_PORT_START" "$BT_PORT_END") || { fail check_deploy_result FAILED "agent(PID:$AGENT_PID) bt port is not listen"; ((ret++)); }  # 检查端口监听状态
    is_port_connected_by_pid "$AGENT_PID"  "$IO_PORT"      || { fail check_deploy_result FAILED "agent(PID:$AGENT_PID) is not connect to gse server"; ((ret++)); }  # 检查端口连接状态

    [ $ret -eq 0 ] && log check_deploy_result DONE "gse agent has been deployed successfully"  # 如果返回值为0则记录部署成功
}

# 日志行转为json格式函数
log_to_json () {
    local date _time log_level step status message
    read -r date _time log_level step status message <<<"$@"

    printf '{"timestamp": "%s", "level": "%s", "step":"%s", "log":"%s","status":"%s"}' \
        "$(date +%s -d "$date $_time")" \
        "$log_level" "$step" "$message" "$status"
}

# 读入LOG_FILE的日志然后批量上报
# 用法：bulk_report_step_status <log_file> <bulk_size:3> <is_urg>
bulk_report_step_status () {
    local log_file=$1  # 日志文件
    local bulk_size=${2:-3}  # 默认批量上报大小为3
    local is_urg=${3:-""}  # 是否紧急上报
    local log_total_line diff
    local bulk_log log=() line json_log
    local tmp_json_body tmp_json_resp

    # 未设置上报API时，直接忽略
    [[ -z "$CALLBACK_URL" ]] && return 0  # 如果未设置上报API则直接返回

    log_total_line=$(wc -l <"$log_file")  # 获取日志文件行数
    diff=$(( log_total_line - LOG_RPT_CNT ))  # 计算差值

    if (( diff >= bulk_size )) || [[ $is_urg = "URG" ]]; then  # 如果差值大于等于批量大小或者是紧急上报
        ((LOG_RPT_CNT++))   #always report from next line
        bulk_log=$(sed -n "${LOG_RPT_CNT},${log_total_line}p" "$log_file")  # 从日志文件中提取需要上报的日志
        # 如果刚好 log_total_line能整除 bulk_size时，最后EXIT的URG调用会触发一个空行
        # 判断如果是空字符串则不上报
        if [[ -z "$bulk_log" ]]; then
            return 0
        fi
    else
        return 0
    fi
    LOG_RPT_CNT=$log_total_line  # 更新上次上报行数

    # 构建log数组
    while read -r line; do
        log+=( "$(log_to_json "$line")" )  # 转换日志行为json格式并存入log数组
    done <<< "$bulk_log"
    # 生成log json array
    json_log=$(printf "%s," "${log[@]}")  # 生成log的json数组字符串
    json_log=${json_log%,}  # 去除末尾逗号

    tmp_json_body=$(mktemp "$TMP_DIR"/nm.reqbody."$(date +%Y%m%d_%H%M%S)".XXXXXX.json)  # 创建临时请求体文件
    tmp_json_resp=$(mktemp "$TMP_DIR"/nm.reqresp."$(date +%Y%m%d_%H%M%S)".XXXXXX.json)  # 创建临时响应文件

    cat > "$tmp_json_body" <<_OO_
{
    "task_id": "$TASK_ID",
    "token": "$TOKEN",
    "logs": [ $json_log ]
}
_OO_

    http_proxy=$HTTP_PROXY https_proxy=$HTTP_PROXY \
        curl -s -S -X POST --retry 5 -d@"$tmp_json_body" "$CALLBACK_URL"/report_log/ -o "$tmp_json_resp"  # 使用curl上报日志
    rm -f "$tmp_json_body" "$tmp_json_resp"  # 移除临时文件
}

report_step_status () {
    local date _time log_level step status message
    local tmp_json_body tmp_json_resp

    # 未设置上报API时，直接忽略
    [ -z "$CALLBACK_URL" ] && return 0  # 如果未设置上报API则直接返回

    read -r date _time log_level step status message <<<"$@"  # 读取日志信息

    tmp_json_body=$(mktemp "$TMP_DIR"/nm.reqbody."$(date +%Y%m%d_%H%M%S)".XXXXXX.json)  # 创建临时请求体文件
    tmp_json_resp=$(mktemp "$TMP_DIR"/nm.reqresp."$(date +%Y%m%d_%H%M%S)".XXXXXX.json)  # 创建临时响应文件

    cat > "$tmp_json_body" <<_OO_
{
    "task_id": "$TASK_ID",
    "token": "$TOKEN",
    "logs": [
        {
            "timestamp": "$(date +%s -d "$date $_time")",
            "level": "$log_level",
            "step": "$step",
            "log": "$message",
            "status": "$status"
        }
    ]
}
_OO_

    http_proxy=$HTTP_PROXY https_proxy=$HTTP_PROXY \
        curl -s -S -X POST --retry 5 -d@"$tmp_json_body" "$CALLBACK_URL"/report_log/ -o "$tmp_json_resp"  # 使用curl上报日志
    rm -f "$tmp_json_body" "$tmp_json_resp"  # 移除临时文件
}

validate_vars_string () {
    echo "$1" | grep -Pq '^[a-zA-Z_][a-zA-Z0-9]+='  # 验证变量名格式是否合法
}

check_pkgtool () {
    _yum=$(command -v yum)
    _apt=$(command -v apt)
    _dnf=$(command -v dnf)

    _curl=$(command -v curl)

    if [ -f "$_curl" ]; then  # 如果curl存在
        return 0
    else
        log check_env - "trying to install curl by package management tool"  # 记录尝试通过包管理工具安装curl
        if [ -f "$_yum" ]; then  # 如果存在yum
            yum -y -q install curl || \
                fail check_env FAILED "install curl failed."  # 安装curl失败则记录失败信息
        elif [ -f "$_apt" ]; then  # 如果存在apt
            apt-get -y install curl || \
                fail check_env FAILED "install curl failed."  # 安装curl失败则记录失败信息
        elif [ -f "$_dnf" ]; then  # 如果存在dnf
            dnf -y -q install curl || \
                fail check_env FAILED "install curl failed."  # 安装curl失败则记录失败信息
        else
            fail check_env FAILED "no curl command found and can not be installed by neither yum,dnf nor apt-get"  # curl命令不存在且无法通过yum、dnf或apt-get安装则记录失败信息
        fi

        log check_env - "curl has been installed"  # 记录curl已安装
    fi
}

check_disk_space () {
    local dir=$1
    if df -x tmpfs -x devtmpfs --output=avail -k "$TMP_DIR" | awk 'NR==2 { if ($1 < 300 * 1024 ) { exit 1 } else {exit 0} }'; then
        log check_env  - "check free disk space. done"  # 记录检查磁盘空间完成
    else
        fail check_env FAILED "no enough space left on $dir"  # 记录磁盘空间不足
    fi
}

check_dir_permission () {
    mkdir -p "$TMP_DIR" || fail check-env FAILED "custom temprary dir '$TMP_DIR' create failed."  # 创建临时目录，失败则记录失败信息

    if ! mktemp "$TMP_DIR/nm.test.XXXXXXXX"; then
        rm "$TMP_DIR"/nm.test.????????  # 若创建临时文件失败则移除
        fail check_env FAILED "create temp files failed in $TMP_DIR"  # 记录创建临时文件失败
    else
        log check_env  - "check temp dir write access: yes"  # 记录检查临时目录写入权限成功
    fi
}

check_download_url () {
    local http_status f

    for f in $PKG_NAME; do
         log check_env - "checking resource($DOWNLOAD_URL/$f) url's validality"  # 记录检查下载链接的有效性
         http_status=$(curl -o /dev/null --silent -Iw '%{http_code}' "$DOWNLOAD_URL/$f")  # 获取HTTP状态码
         if [[ "$http_status" == "200" ]] || [[ "$http_status" == "000" ]]; then
             log check_env - "check resource($DOWNLOAD_URL/$f) url succeed"  # 记录检查资源URL成功
         else
             fail check_env FAILED "check resource($DOWNLOAD_URL/$f) url failed, http_status:$http_status"  # 记录检查资源URL失败
         fi
    done
}

check_target_clean () {
    if [[ -d $AGENT_SETUP_PATH/ ]]; then
        warn check_env - "directory $AGENT_SETUP_PATH is not clean. everything will be wiped unless -u was specified"  # 若AGENT_SETUP_PATH目录不为空则发出警告
    fi
}

backup_for_upgrade () {
    local T
    cd "$AGENT_SETUP_PATH/.." || fail backup_config FAILED "change directory to $AGENT_SETUP_PATH/../ failed"  # 切换目录到AGENT_SETUP_PATH的父目录，失败则记录失败信息

    if [ "$UPGRADE" == "TRUE" ]; then  # 如果是升级操作
        T=$(date +%F_%T)  # 获取当前时间
        log backup_config - "backup configs for agents"  # 记录备份agent配置
        cp -vfr agent/etc "etc.agent.${TASK_ID}.$T"  # 备份agent配置
        log backup_config - "backup configs for plugins (if exists)"  # 记录备份插件配置（如果存在）
        [ -d plugins/etc ] && cp -vrf plugins/etc "etc.plugins.${TASK_ID}.$T"  # 若插件配置目录存在则备份
    fi
}

_help () {
    # 帮助信息
    echo "${0%*/} -i CLOUD_ID -l URL -I LAN_IP [OPTIONS]"

    echo "  -I lan ip address on ethernet "
    echo "  -i CLOUD_ID"
    echo "  -l DOWNLOAD_URL"
    echo "  -s TASK_ID. [optional]"
    echo "  -c TOKEN. [optional]"
    echo "  -u upgrade action. [optional]"
    echo "  -r CALLBACK_URL, [optional]"
    echo "  -x HTTP_PROXY, [optional]"
    echo "  -p AGENT_SETUP_PATH, [optional]"
    echo "  -e BT_FILE_SERVER_IP, [optional]"
    echo "  -a DATA_SERVER_IP, [optional]"
    echo "  -k TASK_SERVER_IP, [optional]"
    echo "  -N UPSTREAM_TYPE, 'server' or 'proxy' [optional]"
    echo "  -T TEMP directory, [optional]"
    echo "  -v CUSTOM VARIABLES ASSIGNMENT LISTS. [optional]"
    echo "     valid variables:"
    echo "         GSE_AGENT_RUN_DIR"
    echo "         GSE_AGENT_DATA_DIR"
    echo "         GSE_AGENT_LOG_DIR"
    echo "  -o enable override OPTION DEFINED VARIABLES by -v. [optional]"
    echo "  -O IO_PORT"
    echo "  -E FILE_SVR_PORT"
    echo "  -A DATA_PORT"
    echo "  -V BTSVR_THRIFT_PORT"
    echo "  -B BT_PORT"
    echo "  -S BT_PORT_START"
    echo "  -Z BT_PORT_END"
    echo "  -K TRACKER_PORT"

    exit 0
}

check_env () {
    local node_type=${1:-$NODE_TYPE}  # 获取节点类型

    log check_env START "checking prerequisite. NETWORK_POLICY,DISK_SPACE,PERMISSION,RESOURCE etc.[PID:$CURR_PID]"  # 记录检查先决条件开始

    [ "$CLOUD_ID" != "0" ] && node_type=pagent  # 如果CLOUD_ID不为0，则节点类型为pagent
    validate_setup_path  # 验证设置路径
    check_polices_${node_type}_to_upstream  # 检查策略
    check_disk_space "$TMP_DIR"  # 检查磁盘空间
    check_dir_permission  # 检查目录权限
    check_pkgtool  # 检查包管理工具
    check_download_url  # 检查下载链接
    check_target_clean  # 检查目标目录是否干净

    log check_env DONE "checking prerequisite done, result: SUCCESS"  # 记录检查先决条件完成
}

# DEFAULT SETTINGS
CLOUD_ID=0  # 云ID，默认为0
TMP_DIR=/tmp  # 临时目录设置为/tmp
AGENT_SETUP_PATH="/usr/local/gse/${NODE_TYPE}"  # 代理设置路径
CURR_PID=$$  # 当前进程ID
UPGRADE=false  # 升级标识，默认为false
OVERIDE=false  # 覆盖标识，默认为false
REMOVE=false  # 移除标识，默认为false
CALLBACK_URL=  # 回调URL
AGENT_PID=  # 代理进程ID
DEBUG=  # 调试标识

# 已上报的日志行数
LOG_RPT_CNT=0  # 已上报的日志行数，默认为0
BULK_LOG_SIZE=3  # 批量日志大小为3

# main program
while getopts I:i:l:s:uc:r:x:p:e:a:k:N:v:oT:RDO:E:A:V:B:S:Z:K: arg; do
    case $arg in
        I) LAN_ETH_IP=$OPTARG ;;  # LAN_ETH_IP 参数赋值
        i) CLOUD_ID=$OPTARG ;;  # CLOUD_ID 参数赋值
        l) DOWNLOAD_URL=${OPTARG%/} ;;  # DOWNLOAD_URL 参数赋值，并去除末尾的斜杠
        s) TASK_ID=$OPTARG ;;  # TASK_ID 参数赋值
        u) UPGRADE=TRUE ;;  # 设置升级标识为TRUE
        c) TOKEN=$OPTARG ;;  # TOKEN 参数赋值
        r) CALLBACK_URL=$OPTARG ;;  # CALLBACK_URL 参数赋值
        x) HTTP_PROXY=$OPTARG; HTTPS_PROXY=$OPTARG ;;  # HTTP_PROXY和HTTPS_PROXY参数赋值
        p) AGENT_SETUP_PATH=$(echo "$OPTARG/$NODE_TYPE" | sed 's|//*|/|g') ;;  # 根据参数设置代理设置路径
        e) read -r -a BT_FILE_SERVER_IP <<< "${OPTARG//,/ }" ;;  # 根据参数设置BT_FILE_SERVER_IP数组
        a) read -r -a DATA_SERVER_IP <<< "${OPTARG//,/ }" ;;  # 根据参数设置DATA_SERVER_IP数组
        k) read -r -a TASK_SERVER_IP <<< "${OPTARG//,/ }" ;;  # 根据参数设置TASK_SERVER_IP数组
        N) UPSTREAM_TYPE=$OPTARG ;;  # UPSTREAM_TYPE 参数赋值
        v) VARS_LIST="$OPTARG" ;;  # VARS_LIST参数赋值
        o) OVERIDE=TRUE ;;  # 设置覆盖标识为TRUE
        T) TMP_DIR=$OPTARG; mkdir -p "$TMP_DIR" ;;  # 设置临时目录，并创建对应目录
        R) REMOVE=TRUE ;;  # 设置移除标识为TRUE
        D) DEBUG=TRUE ;;  # 设置调试标识为TRUE
        O) IO_PORT=$OPTARG ;;  # IO_PORT参数赋值
        E) FILE_SVR_PORT=$OPTARG ;;  # FILE_SVR_PORT参数赋值
        A) DATA_PORT=$OPTARG ;;  # DATA_PORT参数赋值
        V) BTSVR_THRIFT_PORT=$OPTARG ;;  # BTSVR_THRIFT_PORT参数赋值
        B) BT_PORT=$OPTARG ;;  # BT_PORT参数赋值
        S) BT_PORT_START=$OPTARG ;;  # BT_PORT_START参数赋值
        Z) BT_PORT_END=$OPTARG ;;  # BT_PORT_END参数赋值
        K) TRACKER_PORT=$OPTARG ;;  # TRACKER_PORT参数赋值

        *)  _help ;;  # 默认情况下调用_help函数
    esac
done

## 检查自定义环境变量
for var_name in ${VARS_LIST//;/ /}; do  # 遍历VARS_LIST中的变量名
    validate_vars_string "$var_name" || fail "$var_name is not a valid name"  # 验证变量名是否有效

    case ${var_name%=*} in  # 根据变量名进行匹配
        CLOUD_ID | DOWNLOAD_URL | TASK_ID | CALLBACK_URL | HOST_LIST_FILE | NODEMAN_PROXY | AGENT_SETUP_PATH)
            [ "$OVERIDE" == "TRUE" ] || continue ;;  # 如果OVERIDE为TRUE则跳过
        VARS_LIST) continue ;;  # 如果变量名为VARS_LIST则跳过
    esac

    eval "$var_name"  # 执行变量的赋值操作
done

LOG_FILE="$TMP_DIR"/nm.${0##*/}.$TASK_ID  # 设置日志文件路径
DEBUG_LOG_FILE=${TMP_DIR}/nm.${0##*/}.${TASK_ID}.debug  # 设置调试日志文件路径

# redirect STDOUT & STDERR to DEBUG
exec &> >(tee "$DEBUG_LOG_FILE")  # 将标准输出和标准错误重定向到DEBUG_LOG_FILE文件中

log check_env - "Args are: $*"  # 记录日志，记录参数信息
for step in check_env \
            download_pkg \
            remove_crontab \
            remove_agent \
            remove_proxy_if_exists \
            setup_agent \
            setup_startup_scripts \
            check_deploy_result; do
    $step  # 依次执行各步骤
done
