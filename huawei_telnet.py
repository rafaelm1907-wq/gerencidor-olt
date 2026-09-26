"""Cliente Telnet de leitura para CLI Huawei MA5800.

O módulo nunca envia comandos de alteração de configuração. ``config`` é usado
somente para acessar comandos ``display`` que a Huawei expõe nesse contexto.
"""
import re
import socket
import time


# Linhas isoladas com "#" são separadores em `display current-configuration`.
# Um prompt Huawei sempre possui um identificador antes de `#`/`>`.
PROMPT = re.compile(r"(?:^|\n)(?!\s*<)[^\r\n]*[A-Za-z0-9)>][>#]\s*$")


class HuaweiTelnet:
    def __init__(self, host, username, password, port=23, timeout=12):
        self.host, self.username, self.password = host, username, password
        self.port, self.timeout = port, timeout
        self.socket = None
        self.buffer = ""

    def connect(self):
        self.socket = socket.create_connection((self.host, self.port), self.timeout)
        self.socket.settimeout(1)
        self._until("User name:")
        self._send(self.username)
        self._until("User password:")
        self._send(self.password)
        self._prompt()
        return self

    def close(self):
        if self.socket is None:
            return
        try:
            self._send("quit")
        except OSError:
            pass
        try:
            self.socket.close()
        finally:
            self.socket = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *_):
        self.close()

    def _send(self, value):
        self.socket.sendall((value + "\r\n").encode("utf-8"))

    def _read(self, deadline):
        while time.monotonic() < deadline:
            try:
                chunk = self.socket.recv(65535)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("A OLT encerrou a sessão Telnet")
            # Negociação Telnet não é usada por essas OLTs; ignora bytes de controle.
            self.buffer += chunk.decode("utf-8", "replace").replace("\x00", "")
            yield self.buffer
        tail = self.buffer[-500:].replace("\r", "\\r").replace("\n", "\\n")
        raise TimeoutError(f"Tempo limite aguardando resposta Telnet; final: {tail}")

    def _until(self, text):
        deadline = time.monotonic() + self.timeout
        for data in self._read(deadline):
            if text in data:
                result, self.buffer = data, ""
                return result

    def _prompt(self):
        deadline = time.monotonic() + self.timeout
        for data in self._read(deadline):
            if re.search(r"\{\s*<cr>(?:\|\|<K>)?\s*\}?:?", data):
                # A confirmação varia entre famílias Huawei: "{ <cr>||<K> }:"
                # nas MA5800 e "{ <cr>" em MA5683T/MA5600.
                self.socket.sendall(b"\r\n")
                self.buffer = re.sub(r"\{\s*<cr>(?:\|\|<K>)?\s*\}?:?", "", self.buffer)
                continue
            if "---- More" in data:
                # Continua a paginação na própria sessão, preservando o texto já lido.
                self.socket.sendall(b" ")
                self.buffer = re.sub(r"---- More.*?----", "", self.buffer)
                continue
            if PROMPT.search(data):
                result, self.buffer = data, ""
                return result

    def command(self, command):
        self._send(command)
        return self._prompt()

    def enter_config(self):
        output = self.command("enable")
        if "password" in output.lower():
            self._send(self.password)
            output = self._prompt()
        self.command("config")
