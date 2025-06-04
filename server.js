require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

app.use(bodyParser.json());

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Token inválido ou expirado' });
  }
}

// Middleware de autorização (somente admin)
function authorizeAdmin(req, res, next) {
  const user = users.find(u => u.id === req.user.userId);
  if (!user || user.perfil !== 'admin') {
    return res.status(403).json({ message: 'Acesso negado: requer perfil admin' });
  }
  next();
}

// Endpoint para login do usuário
app.post('/api/auth/login', (req, res) => {
  const credentials = req.body;
  const userData = doLogin(credentials);

  if (userData) {
    const token = jwt.sign(
      { userId: userData.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    return res.json({ token });
  }
  
  res.status(401).json({ message: 'Credenciais inválidas' });
});

// Endpoint para dados do usuário logado
app.get('/api/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
  
  // Não retornar a senha
  const { password, ...userWithoutPassword } = user;
  res.json(userWithoutPassword);
});

// Endpoint para recuperação dos dados de todos os usuários cadastrados (apenas admin)
app.get('/api/users', authenticateToken, authorizeAdmin, (req, res) => {
  // Remover senhas dos usuários antes de retornar
  const usersWithoutPasswords = users.map(user => {
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  });
  
  res.status(200).json({ data: usersWithoutPasswords });
});

// Endpoint para recuperação dos contratos existentes (apenas admin)
app.get('/api/contracts/:empresa/:inicio', authenticateToken, authorizeAdmin, (req, res) => {
  try {
    const { empresa, inicio } = req.params;
    
    // Validação básica dos parâmetros
    if (!empresa || !inicio) {
      return res.status(400).json({ message: 'Parâmetros empresa e inicio são obrigatórios' });
    }
    
    const result = getContracts(empresa, inicio);
    res.status(200).json({ data: result || [] });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Mock de dados
const users = [
  {
    "username": "user", 
    "password": "123456", 
    "id": 123, 
    "email": "user@dominio.com",
    "perfil": "user"
  },
  {
    "username": "admin", 
    "password": "123456789", 
    "id": 124, 
    "email": "admin@dominio.com", 
    "perfil": "admin"
  },
  {
    "username": "colab", 
    "password": "123", 
    "id": 125, 
    "email": "colab@dominio.com",
    "perfil": "user"
  },
];

// Funções auxiliares
function doLogin(credentials) {
  return users.find(user => 
    user.username === credentials?.username && 
    user.password === credentials?.password
  );
}

function getContracts(empresa, inicio) {
  // Validação contra SQL Injection
  if (!empresa.match(/^[a-zA-Z0-9\s]+$/) || !inicio.match(/^\d{4}-\d{2}-\d{2}$/)) {
    throw new Error('Parâmetros inválidos');
  }

  // Simulação de repositório seguro
  const repository = new Repository();
  const query = `SELECT * FROM contracts WHERE empresa = ? AND data_inicio = ?`;
  const params = [empresa, inicio];
  
  return repository.execute(query, params);
}

// Classe simulada para acesso ao banco de dados
class Repository {
  execute(query, params) {
    // Simulação: retorna dados fictícios
    if (query.includes('contracts')) {
      return [
        { id: 1, empresa: params[0], data_inicio: params[1], valor: 10000 },
        { id: 2, empresa: params[0], data_inicio: params[1], valor: 15000 }
      ];
    }
    return [];
  }
}

module.exports = app;