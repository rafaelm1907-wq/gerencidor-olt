#!/usr/bin/env python3
"""Cria ou atualiza as contas iniciais sem expor senhas na linha de comando."""
import auth_store


if __name__ == "__main__":
    auth_store.initialize()
    if not auth_store.user_info("admin"):
        auth_store.seed_user("admin", "superadmin", "superadmin", must_change_password=True)
        print("Superadmin inicial criado: admin. A senha padrão será trocada no primeiro acesso.")
    else:
        print("Superadmin existente preservado.")
