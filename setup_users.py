#!/usr/bin/env python3
"""Cria ou atualiza as contas iniciais sem expor senhas na linha de comando."""
import getpass
import os

import auth_store


def password(label, variable):
    value = os.environ.get(variable) or getpass.getpass(label)
    if len(value) < 8:
        raise SystemExit("A senha deve ter ao menos 8 caracteres.")
    return value


def upsert(username, secret, role):
    if auth_store.user_info(username):
        auth_store.set_password(username, secret)
    else:
        auth_store.seed_user(username, secret, role)


if __name__ == "__main__":
    auth_store.initialize()
    viewer = os.environ.get("VIEWER_USERNAME", "viewer")
    upsert("admin", password("Senha inicial do administrador: ", "ADMIN_PASSWORD"), "admin")
    upsert(viewer, password(f"Senha inicial do usuário {viewer}: ", "VIEWER_PASSWORD"), "viewer")
    print(f"Usuários admin e {viewer} configurados.")

