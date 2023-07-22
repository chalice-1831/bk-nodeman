#!/opt/py36/bin/python
# -*- encoding:utf-8 -*-
# vim:ft=python sts=4 sw=4 expandtab nu

from __future__ import print_function

import abc
import argparse
import base64
import ipaddress
import json
import logging
import os
import socket
import sys
import time
import traceback
from functools import partial
from io import StringIO
from pathlib import Path
from subprocess import Popen
from typing import Any, Callable, Dict, List, Optional, Union


def arg_parser() -> argparse.ArgumentParser:
    """Commandline argument parser"""
    parser = argparse.ArgumentParser(description="p-agent setup scripts")
    parser.add_argument("-f", "--config", type=str, help="a file contain p-agent hosts info")
    parser.add_argument(
        "-j",
        "--json",
        type=str,
        help="a file contain p-agent hosts info in json format",
    )
    parser.add_argument("-I", "--lan-eth-ip", type=str, help="local ip address of proxy")
    parser.add_argument(
        "-l",
        "--download-url",
        type=str,
        help="a url for downloading gse agent packages (without filename)",
    )
    parser.add_argument("-s", "--task-id", type=str, help="task id generated by nodeman, optional")
    parser.add_argument("-r", "--callback-url", type=str, help="api for report step and task status")
    parser.add_argument("-c", "--token", type=str, help="token for request callback api")
    parser.add_argument(
        "-T",
        "--temp-dir",
        action="store_true",
        default=False,
        help="directory to save downloaded scripts and temporary files",
    )
    parser.add_argument("-L", "--download-path", type=str, help="Tool kit storage path")

    # 主机信息
    parser.add_argument("-HLIP", "--host-login-ip", type=str, help="Host Login IP")
    parser.add_argument("-HIIP", "--host-inner-ip", type=str, help="Host Inner IP")
    parser.add_argument("-HA", "--host-account", type=str, help="Host Account")
    parser.add_argument("-HP", "--host-port", type=str, help="Host Port")
    parser.add_argument("-HI", "--host-identity", type=str, help="Host Identity")
    parser.add_argument("-HAT", "--host-auth-type", type=str, help="Host Auth Type")
    parser.add_argument("-HC", "--host-cloud", type=str, help="Host Cloud")
    parser.add_argument("-HNT", "--host-node-type", type=str, help="Host Node Type")
    parser.add_argument("-HOT", "--host-os-type", type=str, help="Host Os Type")
    parser.add_argument("-HDD", "--host-dest-dir", type=str, help="Host Dest Dir")
    parser.add_argument("-HPP", "--host-proxy-port", type=int, default=17981, help="Host Proxy Port")
    parser.add_argument("-CPA", "--channel-proxy-address", type=str, help="Channel Proxy Address", default=None)

    parser.add_argument("-HSJB", "--host-solutions-json-b64", type=str, help="Channel Proxy Address", default=None)
    return parser


args = arg_parser().parse_args(sys.argv[1:])

try:
    # import 3rd party libraries here, in case the python interpreter does not have them
    import impacket  # noqa
    import paramiko  # noqa
    import requests  # noqa

    # import psutil

except ImportError as err:
    from urllib import request

    _query_params = json.dumps(
        {
            "task_id": args.task_id,
            "token": args.token,
            "logs": [
                {
                    "timestamp": round(time.time()),
                    "level": "ERROR",
                    "step": "import_3rd_libs",
                    "log": str(err),
                    "status": "FAILED",
                    "prefix": "[proxy]",
                }
            ],
        }
    ).encode()

    req = request.Request(
        f"{args.callback_url}/report_log/",
        data=_query_params,
        headers={"Content-Type": "application/json"},
    )
    request.urlopen(req)
    exit()


# 自定义日志处理器
class ReportLogHandler(logging.Handler):
    def __init__(self, report_log_url):
        super().__init__()
        self._report_log_url = report_log_url

    def emit(self, record):

        if not record.is_report:
            return

        status: str = ("-", "FAILED")[record.levelname == "ERROR"]
        query_params = {
            "task_id": args.task_id,
            "token": args.token,
            "logs": [
                {
                    "timestamp": round(time.time()),
                    "level": record.levelname,
                    "step": record.step,
                    "log": f"[{record.step}]({status}) {record.message}",
                    "status": status,
                    "prefix": "[proxy]",
                }
            ],
        }
        if args.channel_proxy_address:
            proxy_address = {
                "http": args.channel_proxy_address,
                "https": args.channel_proxy_address,
            }
            requests.post(self._report_log_url, json=query_params, proxies=proxy_address)
        else:
            requests.post(self._report_log_url, json=query_params)


class CustomLogger(logging.LoggerAdapter):
    def _log(self, level, msg, *_args, extra=None, **kwargs):
        if extra is None:
            extra = {}

        step: str = extra.pop("step", "N/A")
        is_report: str = extra.pop("is_report", True)
        kwargs = {"step": step, "report": is_report}
        kwargs.update(extra)

        super()._log(level, msg, *_args, extra=kwargs)

    def logging(self, step: str, msg: str, level: int = logging.INFO, is_report: bool = True):
        self._log(level, msg, extra={"step": step, "is_report": is_report})


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(step)s] [%(status)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        ReportLogHandler(f"{args.callback_url}/report_log/"),
    ],
)

logger = CustomLogger(logging.getLogger())


# 默认的连接最长等待时间
DEFAULT_CONNECT_TIMEOUT = 30

# 默认的命令执行最长等待时间
DEFAULT_CMD_RUN_TIMEOUT = 30

DEFAULT_HTTP_PROXY_SERVER_PORT = args.host_proxy_port


def is_ip(ip: str, _version: Optional[int] = None) -> bool:
    """
    判断是否为合法 IP
    :param ip:
    :param _version: 是否为合法版本，缺省表示 both
    :return:
    """
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if _version is None:
        return True
    return ip_address.version == _version


# 判断是否为合法 IPv6
is_v6 = partial(is_ip, _version=6)

# 判断是否为合法 IPv4
is_v4 = partial(is_ip, _version=4)


class DownloadFileError(Exception):
    """文件"""

    pass


def json_b64_decode(json_b64: str) -> Any:
    """
    base64(json_str) to python type
    :param json_b64:
    :return:
    """
    return json.loads(base64.b64decode(json_b64.encode()).decode())


def execute_cmd(
    cmd_str,
    ipaddr,
    username,
    password,
    domain="",
    share="ADMIN$",
    is_no_output=False,
):
    """execute command"""
    try:
        from wmiexec import WMIEXEC
    except ImportError:
        # WMI 执行文件不存在，从下载源同步
        download_file(f"{args.download_url}/wmiexec.py", str(Path(__file__).parent))
        from wmiexec import WMIEXEC

    executor = WMIEXEC(cmd_str, username, password, domain, share=share, noOutput=is_no_output)
    result_data = executor.run(ipaddr)
    return {"result": True, "data": result_data}


def execute_batch_solution(
    login_ip: str,
    account: str,
    identity: str,
    tmp_dir: str,
    execution_solution: Dict[str, Any],
):
    if os.path.isfile(identity):
        logger.logging(
            step="execute_batch_solution",
            msg="identity seems like a key file, which is not supported by windows authentication",
            level=logging.ERROR,
        )

        return False

    for step in execution_solution["steps"]:
        for content in step["contents"]:
            if step["type"] == "dependencies":

                localpath = os.path.join(args.download_path, content["name"])
                # 文件不存在，从下载源同步
                if not os.path.exists(localpath):
                    logger.logging(
                        "execute_batch_solution", f"file -> {content['name']} not exists, sync from {content['text']}"
                    )
                    download_file(content["text"], args.download_path)

                # 构造文件推送命令
                cmd: str = "put {localpath} {tmp_dir}".format(localpath=localpath, tmp_dir=tmp_dir)
            elif step["type"] == "commands":
                cmd: str = content["text"]
            else:
                logger.logging("execute_batch_solution", f"unknown step type -> {step['type']}")
                continue

            logger.logging("send_cmd", cmd)

            try:
                res = execute_cmd(cmd, login_ip, account, identity, is_no_output=content["name"] == "run_cmd")
            except Exception as exc:
                # 过程中只要有一条命令执行失败，视为执行方案失败
                logger.logging("execute_batch_solution", f"execute {cmd} failed, err_msg -> {exc}", level=logging.ERROR)
                return

            print(res)


def execute_shell_solution(
    login_ip: str,
    account: str,
    port: int,
    identity: str,
    auth_type: str,
    os_type: str,
    execution_solution: Dict[str, Any],
):
    client_key_strings: List[str] = []
    if auth_type == "KEY":
        client_key_strings.append(identity)

    # cmds: List[str] = []
    # shell_pkg: str = ("bash", "ksh")[os_type == "aix"]
    with ParamikoConn(
        host=login_ip,
        port=port,
        username=account,
        password=identity,
        client_key_strings=client_key_strings,
        connect_timeout=15,
    ) as conn:
        for step in execution_solution["steps"]:
            # 暂不支持 dependencies 等其他步骤类型
            if step["type"] != "commands":
                continue
            for content in step["contents"]:
                logger.logging("send_cmd", content)
                run_output: RunOutput = conn.run(content, check=True, timeout=10)
                logger.logging("send_cmd", str(run_output), is_report=False)


def is_port_listen(ip: str, port: int) -> bool:
    s = socket.socket((socket.AF_INET, socket.AF_INET6)[is_v6(ip)], socket.SOCK_STREAM)
    r = s.connect_ex((ip, port))

    if r == 0:
        return True
    else:
        return False


def start_http_proxy(ip: str, port: int) -> Any:
    if is_port_listen(ip, port):
        logger.logging("start_http_proxy", "http proxy exists")
    else:
        Popen("/opt/nginx-portable/nginx-portable restart", shell=True)

        time.sleep(5)
        if is_port_listen(ip, port):
            logger.logging("start_http_proxy", "http proxy started")
        else:
            logger.logging("start_http_proxy", "http proxy start failed", level=logging.ERROR)
            raise Exception("http proxy start failed.")


def json_parser(json_file: str) -> List:
    """Resolve formatted lines to object from config file"""

    configs = []

    with open(json_file, "r", encoding="utf-8") as f:
        hosts = json.loads(f.read())
        for host in hosts:
            configs.append(tuple(host))
    return configs


def download_file(url: str, dest_dir: str):
    """get files via http"""
    try:
        local_filename = url.split("/")[-1]
        # NOTE the stream=True parameter below
        local_file = os.path.join(dest_dir, local_filename)

        r = requests.get(url, stream=True)
        r.raise_for_status()

        # 采用覆盖更新策略
        with open(str(local_file), "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                # filter out keep-alive new chunks
                if chunk:
                    f.write(chunk)

    except Exception as exc:
        err_msg: str = f"download file from {url} to {dest_dir} failed: {str(exc)}"
        logger.logging("download_file", err_msg, level=logging.WARNING)
        raise DownloadFileError(err_msg) from exc


def main() -> None:

    login_ip = args.host_login_ip
    user = args.host_account
    port = int(args.host_port)
    identity = args.host_identity
    auth_type = args.host_auth_type
    os_type = args.host_os_type
    tmp_dir = args.host_dest_dir
    host_solutions_json_b64 = args.host_solutions_json_b64

    host_solutions = json_b64_decode(host_solutions_json_b64)
    type__host_solution_map = {host_solution["type"]: host_solution for host_solution in host_solutions}

    # 启动proxy
    start_http_proxy(args.lan_eth_ip, DEFAULT_HTTP_PROXY_SERVER_PORT)

    if os_type not in ["windows"] or (os_type in ["windows"] and port != 445):
        host_solution = type__host_solution_map["shell"]
        execute_shell_solution(
            login_ip=login_ip,
            account=user,
            port=port,
            auth_type=auth_type,
            identity=identity,
            os_type=os_type,
            execution_solution=host_solution,
        )
    else:
        host_solution = type__host_solution_map["batch"]
        execute_batch_solution(
            login_ip=login_ip,
            account=user,
            identity=identity,
            tmp_dir=tmp_dir,
            execution_solution=host_solution,
        )


BytesOrStr = Union[str, bytes]


class RemoteBaseException(Exception):
    pass


class RunCmdError(RemoteBaseException):
    pass


class PermissionDeniedError(RemoteBaseException):
    pass


class DisconnectError(RemoteBaseException):
    pass


class RemoteTimeoutError(RemoteBaseException):
    pass


class ProcessError(RemoteBaseException):
    pass


class RunOutput:
    command: str = None
    exit_status: int = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    def __init__(self, command: BytesOrStr, exit_status: int, stdout: BytesOrStr, stderr: BytesOrStr):
        self.exit_status = exit_status
        self.command = self.bytes2str(command)
        self.stdout = self.bytes2str(stdout)
        self.stderr = self.bytes2str(stderr)

    @staticmethod
    def bytes2str(val: BytesOrStr) -> str:
        if isinstance(val, bytes):
            return val.decode(encoding="utf-8")
        return val

    def __str__(self):
        outputs = [
            f"exit_status: {self.exit_status}",
            f"stdout: {self.stdout}",
            f"stderr: {self.stderr}",
        ]
        return ", ".join(outputs)


class BaseConn(abc.ABC):
    """连接基类"""

    # 连接地址或域名
    host: str = None
    # 连接端口
    port: int = None
    # 登录用户名
    username: str = None
    # 登录密码
    password: Optional[str] = None
    # 登录密钥
    client_key_strings: Optional[List[str]] = None
    # 连接超时时间
    connect_timeout: Union[int, float] = None
    # 检查器列表，用于输出预处理
    inspectors: List[Callable[["BaseConn", RunOutput], None]] = None
    # 连接参数
    options: Dict[str, Any] = None
    # 连接对象
    _conn: Any = None

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        client_key_strings: Optional[List[str]] = None,
        connect_timeout: Optional[Union[int, float]] = None,
        inspectors: List[Callable[["BaseConn", RunOutput], bool]] = None,
        **options,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_key_strings = client_key_strings or []
        self.connect_timeout = (connect_timeout, DEFAULT_CONNECT_TIMEOUT)[connect_timeout is None]
        self.inspectors = inspectors or []
        self.options = options

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError

    @abc.abstractmethod
    def connect(self):
        """
        创建一个连接
        :return:
        :raises:
            KeyExchangeError
            PermissionDeniedError 认证失败
            ConnectionLostError 连接丢失
            RemoteTimeoutError 连接超时
            DisconnectError 远程连接失败
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _run(
        self, command: str, check: bool = False, timeout: Optional[Union[int, float]] = None, **kwargs
    ) -> RunOutput:
        """命令执行"""
        raise NotImplementedError

    def run(
        self, command: str, check: bool = False, timeout: Optional[Union[int, float]] = None, **kwargs
    ) -> RunOutput:
        """
        命令执行
        :param command: 命令
        :param check: 返回码非0抛出 ProcessError 异常
        :param timeout: 命令执行最大等待时间，超时抛出 RemoteTimeoutError 异常
        :param kwargs:
        :return:
        :raises:
            SessionError 回话异常，连接被重置等
            ProcessError 命令执行异常
            RemoteTimeoutError 执行超时
        """
        run_output = self._run(command, check, timeout, **kwargs)
        # 输出预处理
        for inspector in self.inspectors:
            inspector(self, run_output)
        return run_output

    def __enter__(self) -> "BaseConn":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self._conn = None


class ParamikoConn(BaseConn):
    """
    基于 paramiko 实现的同步 SSH 连接
    paramiko
        仓库：https://github.com/paramiko/paramiko
        文档：https://www.paramiko.org/
    """

    _conn: Optional[paramiko.SSHClient] = None

    @staticmethod
    def get_key_instance(key_content: str):
        key_instance = None
        with StringIO(key_content) as key_file:
            for cls in [paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key]:
                try:
                    key_instance = cls.from_private_key(key_file)
                    logger.logging("[get_key_instance]", f"match {cls.__name__}", is_report=False)
                    break
                except paramiko.ssh_exception.PasswordRequiredException:
                    raise PermissionDeniedError("Password is required for the private key")
                except paramiko.ssh_exception.SSHException:
                    logger.logging("[get_key_instance]", f"not match {cls.__name__}, skipped", is_report=False)
                    key_file.seek(0)
                    continue

        if not key_instance:
            raise PermissionDeniedError("Unsupported key type")

        return key_instance

    def close(self):
        self._conn.close()

    def connect(self) -> paramiko.SSHClient:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 仅支持单个密钥
        if self.client_key_strings:
            pkey = self.get_key_instance(self.client_key_strings[0])
        else:
            pkey = None

        # API 文档：https://docs.paramiko.org/en/stable/api/client.html#paramiko.client.SSHClient.connect
        # 认证顺序：
        #  - pkey or key_filename
        #  - Any “id_rsa”, “id_dsa” or “id_ecdsa” key discoverable in ~/.ssh/ (look_for_keys=True)
        #  - username/password auth, if a password was given
        try:
            ssh.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                pkey=pkey,
                password=self.password,
                timeout=self.connect_timeout,
                # 从安全上考虑，禁用本地RSA私钥扫描
                look_for_keys=False,
                **self.options,
            )
        except paramiko.BadHostKeyException as e:
            raise PermissionDeniedError(f"Key verification failed：{e}") from e
        except paramiko.AuthenticationException as e:
            raise PermissionDeniedError(
                f"Authentication failed, please check the authentication information for errors: {e}"
            ) from e
        except (paramiko.SSHException, socket.error, Exception) as e:
            raise DisconnectError(f"Remote connection failed: {e}") from e
        self._conn = ssh
        return ssh

    def _run(
        self, command: str, check: bool = False, timeout: Optional[Union[int, float]] = None, **kwargs
    ) -> RunOutput:

        begin_time = time.time()
        try:
            __, stdout, stderr = self._conn.exec_command(command=command, timeout=timeout)
            # 获取 exit_status 方式参考：https://stackoverflow.com/questions/3562403/
            exit_status = stdout.channel.recv_exit_status()
        except paramiko.SSHException as e:
            if check:
                raise ProcessError(f"Command returned non-zero: {e}")
            # exec_command 方法没有明确抛出 timeout 异常，需要记录调用前后时间差进行抛出
            cost_time = time.time() - begin_time
            if cost_time > timeout:
                raise RemoteTimeoutError(f"Connect timeout：{e}") from e
            exit_status, stdout, stderr = 1, StringIO(""), StringIO(str(e))
        return RunOutput(command=command, exit_status=exit_status, stdout=stdout.read(), stderr=stderr.read())


if __name__ == "__main__":
    try:
        main()
    except Exception as _e:
        logger.logging("proxy_fail", str(_e), level=logging.ERROR)
        logger.logging("proxy_fail", traceback.format_exc(), level=logging.ERROR, is_report=False)
