# Refatoração de Segurança API

## Melhorias Implementadas:
- Substituição do sistema de session-id por JWT
- Tokens agora trafegam via headers (não mais na URL)
- Validação de token em todas as rotas
- Controle de acesso baseado em perfis
- Novo endpoint `/api/me` para dados do usuário logado
- Proteção contra SQL Injection nos parâmetros

## Como Testar:
1. Faça login POST em `/api/auth/login`
2. Use o token recebido no header `Authorization: Bearer <token>`
3. Endpoints disponíveis:
   - GET `/api/me` (todos usuários)
   - GET `/api/users` (apenas admin)
   - GET `/api/contracts/{empresa}/{data}` (apenas admin)
