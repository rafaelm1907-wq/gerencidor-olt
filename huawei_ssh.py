"""Sessão SSH interativa de leitura para equipamentos Huawei."""
import re
import time


PROMPT = re.compile(r"(?:^|\n)(?!\s*<)[^\r\n]*[A-Za-z0-9)>][>#]\s*$")


class HuaweiSSH:
    def __init__(self, host, username, password, port=22, timeout=20):
        self.host, self.username, self.password = host, username, password
        self.port, self.timeout = port, timeout
        self.client = self.channel = None
        self.buffer = ""

    def connect(self):
        import paramiko
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, port=self.port, username=self.username, password=self.password,
                            timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
                            look_for_keys=False, allow_agent=False)
        self.channel = self.client.invoke_shell(width=200, height=1000)
        self.channel.settimeout(1)
        self._prompt()
        return self

    def close(self):
        try:
            if self.channel: self.channel.close()
        finally:
            if self.client: self.client.close()
            self.channel = self.client = None

    def __enter__(self): return self.connect()
    def __exit__(self, *_): self.close()

    def _send(self, value): self.channel.send(value + "\r\n")

    def _prompt(self):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(65535)
                if not chunk: raise ConnectionError("A OLT encerrou a sessão SSH")
                self.buffer += chunk.decode("utf-8", "replace").replace("\x00", "")
                if re.search(r"\{\s*<cr>(?:\|\|<K>)?\s*\}?:?", self.buffer):
                    self.channel.send("\r\n")
                    self.buffer = re.sub(r"\{\s*<cr>(?:\|\|<K>)?\s*\}?:?", "", self.buffer)
                    continue
                if "---- More" in self.buffer:
                    self.channel.send(" ")
                    self.buffer = re.sub(r"---- More.*?----", "", self.buffer)
                    continue
                if PROMPT.search(self.buffer):
                    result, self.buffer = self.buffer, ""
                    return result
            time.sleep(.05)
        tail = self.buffer[-500:].replace("\r", "\\r").replace("\n", "\\n")
        raise TimeoutError(f"Tempo limite aguardando resposta SSH; final: {tail}")

    def command(self, command):
        self._send(command)
        return self._prompt()

    def enter_config(self):
        output = self.command("enable")
        if "password" in output.lower():
            self._send(self.password)
            self._prompt()
        self.command("config")
